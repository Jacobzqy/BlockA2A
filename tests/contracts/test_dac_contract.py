# tests/test_data_anchoring_contract.py
from __future__ import annotations

import os
from typing import List, Tuple, NewType

import pytest
from eth_abi.packed import encode_packed
from solcx import compile_files, install_solc
from web3 import Web3, HTTPProvider
from web3.exceptions import ContractLogicError

# ---------------------------------------------------------------------------
#  1. 引入 utils.bn256 BLS 实现
# ---------------------------------------------------------------------------
from src.blocka2a.utils import bn256 as bls

# 类型别名
SecretKey = NewType("SecretKey", int)
Signature = NewType("Signature", Tuple[int, int])

# 与合约保持一致的 DST
DOMAIN = b"DAC"

# ---------------------------------------------------------------------------
#  2. 私钥列表（应对应合约里的硬编码 G2 公钥）
# ---------------------------------------------------------------------------
PRIVATE_KEYS: List[SecretKey] = [
    SecretKey(2833825224628770647255613288651483959178104459000430758204801703807178990217),
    SecretKey(19020176885312313733264572853669371179783749614111895563810414749642828590597),
    SecretKey(17209595577509179005721276854579044608748368966654267456114674148343750200167),
    SecretKey(15552513599869556358546192840299715781861744334503987525011545606),
    SecretKey(8283205931288848621696243456090300950392495072752410166429143470090943695348),
]

# ---------------------------------------------------------------------------
#  3. 辅助函数
# ---------------------------------------------------------------------------
def print_header(title: str) -> None:
    sep = "=" * 76
    print(f"\n{sep}\n// {title.upper()}\n{sep}")

def create_payload(data_hash: bytes, milestone: str) -> bytes:
    """
    构造与合约 abi.encodePacked(bytes32, string, string) 完全一致的字节串:
      encode_packed([data_hash, "|", milestone])
    """
    return encode_packed(
        ["bytes32", "string", "string"],
        [data_hash, "|", milestone]
    )

def serialize_signature(sig: Signature) -> List[int]:
    """
    将 bls.Signature (FQ, FQ) 转成 [x, y] 两元素 Python int 列表，以便传给合约。
    """
    x_fq, y_fq = sig  # sig 来自 bls.sign 返回的 (FQ, FQ)
    # FQ 对象存储在 .n 属性
    return [int(x_fq.n), int(y_fq.n)]

# ---------------------------------------------------------------------------
#  4. Pytest 固定配置
# ---------------------------------------------------------------------------
GANACHE_URL = "http://127.0.0.1:8545"
SOLC_VERSION = "0.8.23"

TEST_DIR     = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(TEST_DIR, "..", ".."))
CONTRACT_SRC = os.path.join(PROJECT_ROOT, "contracts", "main", "DataAnchoringContract.sol")
ALLOWED_PATH = [os.path.join(PROJECT_ROOT, "contracts")]

# ---------------------------------------------------------------------------
#  5. Pytest fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def w3():
    print_header("Setup: Connecting to local chain")
    w3 = Web3(HTTPProvider(GANACHE_URL))
    assert w3.is_connected(), "无法连接到本地节点，请确保 Ganache/Anvil 已启动"
    return w3

@pytest.fixture(scope="session")
def owner(w3):
    return w3.eth.accounts[0]

@pytest.fixture(scope="session")
def compiled_contract():
    print_header(f"Setup: Compiling contract with solc {SOLC_VERSION}")
    try:
        install_solc(SOLC_VERSION)
    except:
        pass
    compiled = compile_files(
        [CONTRACT_SRC],
        allow_paths=ALLOWED_PATH,
        solc_version=SOLC_VERSION,
        optimize=True,
        optimize_runs=200,
    )
    key = f"{CONTRACT_SRC}:DataAnchoringContract"
    assert key in compiled, "未找到 DataAnchoringContract 的编译产物"
    return compiled[key]

@pytest.fixture(scope="module")
def dac_contract(w3, owner, compiled_contract):
    print_header("Setup: Deploying contract")
    Contract = w3.eth.contract(
        abi=compiled_contract["abi"],
        bytecode=compiled_contract["bin"]
    )
    tx_hash = Contract.constructor().transact({"from": owner})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    addr = receipt["contractAddress"]
    print(f"✅ Contract deployed at {addr}")
    return w3.eth.contract(address=addr, abi=compiled_contract["abi"])

# ---------------------------------------------------------------------------
#  6. 测试用例
# ---------------------------------------------------------------------------
def test_anchor_and_duplicate_guard(dac_contract, owner, w3):
    print_header("Test 1: Anchor & duplicate guard")
    data_hash = b"\xaa" * 32
    cid       = "QmExample"
    expiry    = w3.eth.get_block("latest")["timestamp"] + 3600

    # 首次锚定成功
    tx = dac_contract.functions.anchor(data_hash, cid, expiry, "init").transact({"from": owner})
    w3.eth.wait_for_transaction_receipt(tx)

    # 重复锚定应失败
    with pytest.raises(ContractLogicError, match="already anchored"):
        dac_contract.functions.anchor(data_hash, "cid2", expiry + 1, "dup").transact({"from": owner})

def test_update_with_valid_aggregate(dac_contract, owner, w3):
    print_header("Test 2: Valid aggregate update")
    data_hash = b"\xbb" * 32
    expiry    = w3.eth.get_block("latest")["timestamp"] + 3600
    dac_contract.functions.anchor(data_hash, "cid-valid", expiry, "pending").transact({"from": owner})

    milestone = "m-verified"
    signer_indices = [0, 1, 2]
    mask = sum(1 << i for i in signer_indices)

    payload = create_payload(data_hash, milestone)
    # 每个 signer 用 bls.sign，内含完整 hash_to_g1
    sigs: List[Signature] = [
        bls.sign(payload, PRIVATE_KEYS[i], DOMAIN) for i in signer_indices
    ]
    agg_sig = bls.aggregate_sigs(sigs)
    agg_ser = serialize_signature(agg_sig)

    # 调用合约 update
    dids = ["did:a", "did:b", "did:c"]
    tx = dac_contract.functions.update(agg_ser, data_hash, milestone, dids, mask) \
        .transact({"from": owner})
    w3.eth.wait_for_transaction_receipt(tx)

    # 验证状态后缀“_verified”
    _, _, _, status = dac_contract.functions.get(data_hash).call()
    assert status == milestone + "_verified"

def test_update_with_invalid_signature(dac_contract, owner, w3):
    print_header("Test 3: Invalid signature rejected")
    data_hash = b"\xcc" * 32
    expiry    = w3.eth.get_block("latest")["timestamp"] + 3600
    dac_contract.functions.anchor(data_hash, "cid-invalid", expiry, "ready").transact({"from": owner})

    milestone = "m-fail"
    payload = create_payload(data_hash, milestone)
    # 用索引4私钥签名，但 mask 只选 0 位 → 验证应失败
    bad_sig = bls.sign(payload, PRIVATE_KEYS[4], DOMAIN)
    bad_ser = serialize_signature(bad_sig)
    bad_mask = 1 << 0

    with pytest.raises(ContractLogicError, match="BLS verify failed"):
        dac_contract.functions.update(bad_ser, data_hash, milestone, ["did:bad"], bad_mask) \
            .transact({"from": owner})
