# tests/test_data_anchoring_contract.py
from __future__ import annotations

import os
from typing import List, Tuple, NewType

import pytest
from eth_abi.packed import encode_packed               # abi.encodePacked 等价函数
from solcx import compile_files, install_solc
from web3 import Web3, HTTPProvider
from web3.exceptions import ContractLogicError
from py_ecc.bn128 import FQ, FQ2, Z1                    # 仅用于类型注解

# --------------------------------------------------------------------------- #
#  1.  本地 BLS-BN254 实现（utils.bn256）
# --------------------------------------------------------------------------- #
from src.blocka2a.utils import new as bn256

SecretKey  = NewType("SecretKey", int)
PointG1    = Tuple[FQ, FQ]
PublicKey  = NewType("PublicKey", Tuple[FQ2, FQ2])
Signature  = NewType("Signature", PointG1)

DOMAIN = b"DAC"        # 必须与 Solidity 端一致

# 五把固定私钥 —— *需保证* DataAnchoringContract.sol 里有相应的 G2 公钥
PRIVATE_KEYS = [
    SecretKey(2833825224628770647255613288651483959178104459000430758204801703807178990217),
    SecretKey(19020176885312313733264572853669371179783749614111895563810414749642828590597),
    SecretKey(17209595577509179005721276854579044608748368966654267456114674148343750200167),
    SecretKey(15552513599869556358546192840299715781861744391901239924434503987525011545606),
    SecretKey(8283205931288848621696243456090300950392495072752410166429143470090943695348)
]

# --------------------------------------------------------------------------- #
# 2.  测试-辅助函数
# --------------------------------------------------------------------------- #
def print_header(title: str) -> None:
    line = "=" * 76
    print(f"\n{line}\n// {title.upper()}\n{line}")

def create_msg_hash_for_signing(data_hash: bytes, milestone: str) -> PointG1:
    """
    构造与 Solidity 端完全一致的待签名消息：
        abi.encodePacked(bytes32 dataHash, string "|", string milestone)
    再调用 utils.bn256.hash_to_g1(payload, DOMAIN)
    """
    payload = encode_packed(["bytes32", "string", "string"], [data_hash, "|", milestone])
    return bn256.hash_to_g1(payload, DOMAIN)

def sign(point: PointG1, sk: SecretKey) -> Signature:
    return bn256.Signature(bn256.multiply(point, sk))   # 直接乘私钥即可

def aggregate_sigs(sigs: List[Signature]) -> Signature:
    return bn256.aggregate_sigs(sigs) if sigs else bn256.Signature(Z1)

# --------------------------------------------------------------------------- #
# 3.  Pytest 固定参数
# --------------------------------------------------------------------------- #
GANACHE_URL  = "http://127.0.0.1:8545"
SOLC_VERSION = "0.8.23"

# ＊根据实际路径修改下列两行＊
TEST_DIR     = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(TEST_DIR, ".."))
CONTRACT_SRC = os.path.join(PROJECT_ROOT, "contracts", "main", "DataAnchoringContract.sol")
ALLOWED_PATH = [os.path.join(PROJECT_ROOT, "contracts")]

# --------------------------------------------------------------------------- #
# 4.  Pytest fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="session")
def w3():
    print_header("Setup: Connecting to local chain")
    w3 = Web3(HTTPProvider(GANACHE_URL))
    assert w3.is_connected(), "无法连接到本地链，请先启动 Ganache / Anvil"
    return w3

@pytest.fixture(scope="session")
def owner(w3):
    return w3.eth.accounts[0]

@pytest.fixture(scope="session")
def compiled_contract():
    print_header(f"Setup: Compiling with solc {SOLC_VERSION}")
    try:
        install_solc(SOLC_VERSION)
    except Exception:
        pass
    compiled = compile_files(
        [CONTRACT_SRC],
        allow_paths=ALLOWED_PATH,
        solc_version=SOLC_VERSION,
        optimize=True,
        optimize_runs=200,
    )
    key = f"{CONTRACT_SRC}:DataAnchoringContract"
    assert key in compiled, "未找到合约编译结果"
    return compiled[key]

@pytest.fixture(scope="module")
def dac_contract(w3, owner, compiled_contract):
    print_header("Setup: Deploying contract")
    Contract = w3.eth.contract(abi=compiled_contract["abi"], bytecode=compiled_contract["bin"])
    tx_hash  = Contract.constructor().transact({"from": owner})
    addr     = w3.eth.wait_for_transaction_receipt(tx_hash)["contractAddress"]
    print(f"✅ 部署成功 @ {addr}")
    return w3.eth.contract(address=addr, abi=compiled_contract["abi"])

# --------------------------------------------------------------------------- #
# 5.  测试用例
# --------------------------------------------------------------------------- #
def test_anchor_and_duplicates(dac_contract, owner, w3):
    print_header("Test-1  Anchor & duplicate guard")
    data_hash = b"\x11" * 32
    expiry    = w3.eth.get_block("latest")["timestamp"] + 3600
    tx = dac_contract.functions.anchor(data_hash, "cid-ok", expiry, "init").transact({"from": owner})
    w3.eth.wait_for_transaction_receipt(tx)

    # 再次锚定同一 hash → 应抛错
    with pytest.raises(ContractLogicError, match="already anchored"):
        dac_contract.functions.anchor(data_hash, "dup", expiry, "dup").transact({"from": owner})

def test_update_with_valid_aggregate(dac_contract, owner, w3):
    print_header("Test-2  Valid aggregate update")
    data_hash = b"\x22" * 32
    expiry    = w3.eth.get_block("latest")["timestamp"] + 3600
    dac_contract.functions.anchor(data_hash, "cid-agg", expiry, "pending").transact({"from": owner})

    milestone      = "milestone-verified"
    signer_indices = [0, 1, 2]
    pks_mask       = sum(1 << i for i in signer_indices)

    # 1) 构造消息点
    msg_pt = create_msg_hash_for_signing(data_hash, milestone)

    # 2) 计算各自签名
    sigs = [sign(msg_pt, PRIVATE_KEYS[i]) for i in signer_indices]

    # 3) 聚合并序列化
    agg_sig = aggregate_sigs(sigs)
    agg_sig_ser = [agg_sig[0].n, agg_sig[1].n]

    # 4) 调用合约 update
    dids = ["did:ok:1", "did:ok:2", "did:ok:3"]
    tx = dac_contract.functions.update(
        agg_sig_ser, data_hash, milestone, dids, pks_mask
    ).transact({"from": owner})
    w3.eth.wait_for_transaction_receipt(tx)

    # 5) 校验状态
    _, _, _, status = dac_contract.functions.get(data_hash).call()
    assert status == milestone + "_verified"

def test_update_with_invalid_signature(dac_contract, owner, w3):
    print_header("Test-3  Invalid signature rejected")
    data_hash = b"\x33" * 32
    expiry    = w3.eth.get_block("latest")["timestamp"] + 3600
    dac_contract.functions.anchor(data_hash, "cid-bad", expiry, "todo").transact({"from": owner})

    milestone = "milestone-bad"
    # 用第四把私钥签，但 mask 只声明第 0 位
    msg_pt   = create_msg_hash_for_signing(data_hash, milestone)
    bad_sig  = sign(msg_pt, PRIVATE_KEYS[4])
    bad_ser  = [bad_sig[0].n, bad_sig[1].n]
    bad_mask = 1 << 0

    with pytest.raises(ContractLogicError, match="BLS verify failed"):
        dac_contract.functions.update(
            bad_ser, data_hash, milestone, ["did:oops"], bad_mask
        ).transact({"from": owner})
