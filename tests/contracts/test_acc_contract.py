import pytest
import os
import re
import time
from web3 import Web3, HTTPProvider
from web3.exceptions import ContractLogicError
from solcx import compile_files, install_solc
from typing import List, Tuple
from eth_abi.packed import encode_packed

# --------------------------------------------------------------------
# 1. 导入和配置 (无变化)
# --------------------------------------------------------------------
from src.blocka2a.utils.bn256 import (
    sign, aggregate_sigs, SecretKey, PublicKey, Signature, multiply, G2
)

GANACHE_URL = "http://127.0.0.1:8545"
SOLC_VERSION = '0.8.23'
_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_TEST_DIR, '..', '..'))
CONTRACT_PATH = os.path.join(_PROJECT_ROOT, 'contracts', 'main', 'AccessControlContract.sol')
ALLOWED_PATHS = [os.path.join(_PROJECT_ROOT, 'contracts')]

# --- 测试数据 (无变化) ---
_SK_INTS = [
    0x643e363881b0025f8dc45f3f27582fa2b5384a6d5c0bee562abcd3d316b6289,  # set-1
    0x2a0d09e2e6d1534982cee88e95192028b3038c4eb3c18891a73a4de87eccae05,  # set-2
    0x260c4931ab5ddbe85345be774b19ad89893e2b6158d92bbab4c92d4afdae0b67,  # set-3
    0x2262692708697740fa77d1b5929c87b72ae2acc3fc1706670397a01abf929e06,  # set-4
    0x125020dfe0a1f5230ae89f5bca09fd946c99cec29f3d8996c32367dcd6eb89f4,  # set-5
]
oracle_sks = [SecretKey(int(sk)) for sk in _SK_INTS]
oracle_pks = [multiply(G2, sk) for sk in oracle_sks]


# --------------------------------------------------------------------
# 辅助函数和 Fixtures (无变化)
# --------------------------------------------------------------------
def format_pk_for_contract(pk: PublicKey) -> Tuple[int, int, int, int]:
    return (pk[0].coeffs[0].n, pk[0].coeffs[1].n, pk[1].coeffs[0].n, pk[1].coeffs[1].n)


def format_sig_for_contract(sig: Signature) -> Tuple[int, int]:
    return (sig[0].n, sig[1].n)


def increase_time(w3, seconds: int):
    """时间旅行辅助函数"""
    print(f"--- 模拟快进区块链时间 {seconds} 秒 ---")
    w3.provider.make_request("evm_increaseTime", [seconds])
    w3.provider.make_request("evm_mine", [])


@pytest.fixture(scope="module")
def w3_and_accounts():
    w3 = Web3(HTTPProvider(GANACHE_URL))
    assert w3.is_connected()
    return w3, w3.eth.accounts


@pytest.fixture(scope="module")
def compiled_contract():
    """编译合约"""
    install_solc(SOLC_VERSION)
    compiled_sol = compile_files(
        [CONTRACT_PATH], allow_paths=ALLOWED_PATHS, solc_version=SOLC_VERSION,
        optimize=True, optimize_runs=200, via_ir=True
    )
    return compiled_sol[f'{CONTRACT_PATH}:AccessControlContract']


@pytest.fixture(scope="function")
def acc_contract(compiled_contract, w3_and_accounts):
    """部署一个新的 ACC 合约实例"""
    w3, accounts = w3_and_accounts
    deployer = accounts[0]

    bytecode_from_compiler = compiled_contract['bin']
    clean_bytecode = '0x' + "".join(re.findall(r'[0-9a-fA-F]+', bytecode_from_compiler))

    Contract = w3.eth.contract(abi=compiled_contract['abi'], bytecode=clean_bytecode)

    tx_hash = Contract.constructor().transact({'from': deployer})

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"\n--- 合约已部署在: {receipt['contractAddress']} ---")
    return w3.eth.contract(address=receipt['contractAddress'], abi=compiled_contract['abi'])


# --------------------------------------------------------------------
#  单一的、端到端的核心流程测试
# --------------------------------------------------------------------

def test_full_lifecycle_final_attempt(acc_contract, w3_and_accounts):
    """最终尝试：完整生命周期测试，修正所有已知问题"""
    w3, accounts = w3_and_accounts
    user = accounts[1]

    # --- 定义测试变量 ---
    resource_id = "/data/patient/final"
    action_id = "read"
    agent_did = "did:blocka2a:userfinal"

    # --- 1. 注册第一个策略 (无需签名) ---
    print("\n步骤 1: 注册第一个策略 (DIDATTRIBUTE)")
    required_sigs = 2
    policy_type_1 = "DIDATTRIBUTE"
    # 对于此类型，policyParameters是象征性的，我们用空数组
    policy_params_1_value = []

    register_params_1 = (
        resource_id, action_id, policy_type_1, policy_params_1_value,
        required_sigs, (0, 0), 0
    )

    receipt_1 = w3.eth.wait_for_transaction_receipt(
        acc_contract.functions.registerPolicy(register_params_1).transact({'from': user})
    )
    assert receipt_1.status == 1, "注册第一个策略失败"
    print("✅ 第一个策略注册成功！")

    # --- 2. 注册第二个策略 (需要签名) ---
    print("\n步骤 2: 注册第二个策略 (ENVIRONMENTAL)，需要签名")
    policy_type_2 = "ENVIRONMENTAL"
    policy_params_2_value = [("maxRisk", "low")]  # (string, string)[]
    policy_params_2_encoded = encode_packed(['string', 'string'], policy_params_2_value[0])

    # 准备签名
    policy_key = w3.keccak(encode_packed(['string', 'string', 'string'], [resource_id, "|", action_id]))
    entry_before_add = acc_contract.functions._policies(policy_key).call()
    nonce_before_add = entry_before_add[1]

    payload_for_add = encode_packed(
        ['string', 'string', 'string', 'bytes32', 'uint256'],
        [resource_id, action_id, policy_type_2,
         w3.keccak(w3.codec.encode(['(string,string)[]'], [policy_params_2_value])), nonce_before_add]
    )

    signer_indices = [0, 1]
    pks_mask = sum(1 << i for i in signer_indices)
    sks_to_use = [oracle_sks[i] for i in signer_indices]
    sigs_add = [sign(payload_for_add, sk, domain=b"ACC") for sk in sks_to_use]
    agg_sig_add = format_sig_for_contract(aggregate_sigs(sigs_add))

    register_params_2 = (
        resource_id, action_id, policy_type_2, policy_params_2_value,
        required_sigs, agg_sig_add, pks_mask
    )

    receipt_2 = w3.eth.wait_for_transaction_receipt(
        acc_contract.functions.registerPolicy(register_params_2).transact({'from': user})
    )
    assert receipt_2.status == 1, "注册第二个策略失败"
    print("✅ 第二个策略注册成功！")

    # 验证现在有两个策略
    policies = acc_contract.functions.getPolicy(resource_id, action_id).call()
    assert len(policies) == 2

    # --- 3. 评估和分发Token ---
    print("\n步骤 3: 评估并分发Token")
    # 假设外部库逻辑通过（因为我们已注释掉它们）
    receipt_eval = w3.eth.wait_for_transaction_receipt(
        acc_contract.functions.evaluate(agent_did, resource_id, action_id).transact({'from': user})
    )
    assert receipt_eval.status == 1
    print("✅ Token分发成功！")

    # --- 4. 注销第一个策略 (DIDATTRIBUTE) ---
    print("\n步骤 4: 注销第一个策略 (DIDATTRIBUTE)")

    # 准备签名
    entry_before_remove = acc_contract.functions._policies(policy_key).call()
    nonce_before_remove = entry_before_remove[1]

    # 这次，我们要移除的策略的 policyParameters 是空数组 `[]`
    # 我们需要正确地计算它的哈希
    params_1_encoded_formal = w3.codec.encode(['(string,string)[]'], [[]])
    params_1_hash = w3.keccak(params_1_encoded_formal)

    payload_for_remove = encode_packed(
        ['string', 'string', 'string', 'bytes32', 'uint256'],
        [resource_id, action_id, policy_type_1, params_1_hash, nonce_before_remove]
    )

    sigs_remove = [sign(payload_for_remove, sk, domain=b"ACC") for sk in sks_to_use]
    agg_sig_remove = format_sig_for_contract(aggregate_sigs(sigs_remove))

    remove_params = (
        resource_id, action_id, policy_type_1,
        [], agg_sig_remove, pks_mask
    )

    receipt_remove = w3.eth.wait_for_transaction_receipt(
        acc_contract.functions.removePolicy(remove_params).transact({'from': user})
    )
    assert receipt_remove.status == 1, "注销第一个策略失败"
    print("✅ 第一个策略注销成功！")

    # 验证现在只剩一个策略
    policies_after_remove = acc_contract.functions.getPolicy(resource_id, action_id).call()
    assert len(policies_after_remove) == 1
    assert policies_after_remove[0][0] == 2  # 剩下的是 ENVIRONMENTAL
    print("✅ 验证策略数量正确！")
    print("\n🎉🎉🎉 所有核心流程测试通过！ 🎉🎉🎉")