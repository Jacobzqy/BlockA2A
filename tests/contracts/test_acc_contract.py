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
from src.blocka2a.utils.new import (
    sign, aggregate_sigs, SecretKey, PublicKey, Signature, multiply, G2
)

GANACHE_URL = "http://127.0.0.1:8545"
SOLC_VERSION = '0.8.23'
_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_TEST_DIR, '..', '..'))
CONTRACT_PATH = os.path.join(_PROJECT_ROOT, 'contracts', 'main', 'AccessControlContract.sol')
ALLOWED_PATHS = [os.path.join(_PROJECT_ROOT, 'contracts')]

# --- 测试数据 (无变化) ---
oracle_sks = [SecretKey(i + 1) for i in range(5)]
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

def test_simple_policy_and_token_lifecycle(acc_contract, w3_and_accounts):
    """一个完整的、简化的生命周期测试：注册 -> 验证 -> 评估 -> 分发 -> 验证Token -> 注销"""
    w3, accounts = w3_and_accounts
    user = accounts[1]

    # --- 定义测试变量 ---
    resource_id = "/data/patient/12345"
    action_id = "view"
    agent_did = "did:blocka2a:user01"
    required_sigs_for_removal = 2

    # --- 1. 注册策略 (Register Policy) ---
    print("\n步骤 1: 首次注册一个 'DIDATTRIBUTE' 策略")
    empty_params_array = []

    register_params = (
        resource_id, action_id, "DIDATTRIBUTE", empty_params_array,
        required_sigs_for_removal, (0, 0), 0
    )

    tx_hash_reg = acc_contract.functions.registerPolicy(register_params).transact({'from': user})
    receipt_reg = w3.eth.wait_for_transaction_receipt(tx_hash_reg)
    assert receipt_reg.status == 1, "注册策略失败"
    print("✅ 策略注册成功！")

    # --- 2. 验证策略 (Verify Policy) ---
    print("\n步骤 2: 验证刚刚注册的策略是否存在")
    policies = acc_contract.functions.getPolicy(resource_id, action_id).call()
    assert len(policies) == 1
    assert policies[0][0] == 1
    print("✅ 策略验证成功！")

    # --- 3. 分发Token (Distribute Token) ---
    print("\n步骤 3: 评估访问请求并分发Token")
    tx_hash_eval = acc_contract.functions.evaluate(agent_did, resource_id, action_id).transact({'from': user})
    receipt_eval = w3.eth.wait_for_transaction_receipt(tx_hash_eval)
    assert receipt_eval.status == 1, "评估或分发Token失败"

    token_issued_logs = acc_contract.events.TokenIssued().get_logs()
    issued_token_args = token_issued_logs[-1]['args']
    print("✅ Token分发成功！")

    # --- 4. 验证Token (Verify Token) ---
    print("\n步骤 4: 验证Token的有效性和过期机制")
    token_struct = (
        issued_token_args['agentDID'], issued_token_args['actionIdentifier'],
        issued_token_args['resourceIdentifier'], issued_token_args['expiry']
    )
    token_hash = acc_contract.functions.getTokenHash(token_struct).call()

    assert acc_contract.functions.verifyTokenHash(token_hash).call() is True
    print("✅ Token当前有效。")

    increase_time(w3, 3601)

    assert acc_contract.functions.verifyTokenHash(token_hash).call() is False
    print("✅ Token已按预期过期。")

    # --- 5. 注销策略 (Remove Policy) ---
    print("\n步骤 5: 使用多重签名注销策略")
    policy_key = w3.keccak(encode_packed(['string', 'string', 'string'], [resource_id, "|", action_id]))

    # 调用 _policies getter，返回的元组是 (requiredSigs, nonce, exists)
    entry = acc_contract.functions._policies(policy_key).call()
    # 【最终修正】nonce 是返回元组的第二个元素，索引为1
    current_nonce = entry[1]

    # 准备签名
    params_hash = w3.keccak(b'\x00' * 32)  # 首次注册时 policyParameters 是空数组，编码后是空字节串
    payload_to_sign = encode_packed(
        ['string', 'string', 'string', 'bytes32', 'uint256'],
        [resource_id, action_id, "DIDATTRIBUTE", params_hash, current_nonce]
    )

    signer_indices = [0, 1]
    pks_mask = sum(1 << i for i in signer_indices)
    sks_to_use = [oracle_sks[i] for i in signer_indices]
    sigs = [sign(payload_to_sign, sk, domain=b"ACC") for sk in sks_to_use]
    agg_sig = format_sig_for_contract(aggregate_sigs(sigs))

    # 构造移除参数
    remove_params = (
        resource_id, action_id, "DIDATTRIBUTE",
        empty_params_array, agg_sig, pks_mask
    )

    tx_hash_remove = acc_contract.functions.removePolicy(remove_params).transact({'from': user})
    receipt_remove = w3.eth.wait_for_transaction_receipt(tx_hash_remove)
    assert receipt_remove.status == 1, "注销策略失败"
    print("✅ 策略注销成功！")

    # 验证策略已被删除
    with pytest.raises(ContractLogicError, match="ACC: policy not found"):
        acc_contract.functions.getPolicy(resource_id, action_id).call()
    print("✅ 策略已不存在，生命周期测试完成！")