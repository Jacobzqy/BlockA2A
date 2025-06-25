import pytest
import os
import time
from web3 import Web3, HTTPProvider
from web3.exceptions import ContractLogicError
from solcx import compile_files, install_solc
from typing import List, Tuple
from eth_abi.packed import encode_packed

# --------------------------------------------------------------------
# 1. 导入和配置
# --------------------------------------------------------------------
from src.blocka2a.utils.new import (
    sign, aggregate_sigs, SecretKey, PublicKey, Signature, multiply, G2
)

GANACHE_URL = "http://127.0.0.1:8545"
SOLC_VERSION = '0.8.23'
_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_TEST_DIR, '..', '..'))
CONTRACT_PATH = os.path.join(_PROJECT_ROOT, 'contracts', 'main', 'InteractionLogicContract.sol')  # 假设这是您修正后的合约
ALLOWED_PATHS = [os.path.join(_PROJECT_ROOT, 'contracts')]

# --- 测试数据 ---
oracle_sks = [SecretKey(i + 1) for i in range(5)]
oracle_pks = [multiply(G2, sk) for sk in oracle_sks]


# --------------------------------------------------------------------
# 辅助函数和 Fixtures
# --------------------------------------------------------------------
def format_pk_for_contract(pk: PublicKey) -> Tuple[int, int, int, int]:
    return (pk[0].coeffs[0].n, pk[0].coeffs[1].n, pk[1].coeffs[0].n, pk[1].coeffs[1].n)


def format_sig_for_contract(sig: Signature) -> Tuple[int, int]:
    return (sig[0].n, sig[1].n)


def increase_time(w3, seconds: int):
    """一个“时间旅行”辅助函数，用于在测试中快进区块链时间"""
    print(f"--- advancing blockchain time by {seconds} seconds ---")
    w3.provider.make_request("evm_increaseTime", [seconds])
    w3.provider.make_request("evm_mine", [])  # 必须挖一个块来让时间变化生效


@pytest.fixture(scope="module")
def w3_and_accounts():
    w3 = Web3(HTTPProvider(GANACHE_URL))
    assert w3.is_connected()
    return w3, w3.eth.accounts


@pytest.fixture(scope="module")
def compiled_contract():
    """编译合约，整个测试会话只执行一次。"""
    install_solc(SOLC_VERSION)
    print("\nCompiling contracts with optimizer and via-IR enabled...")
    compiled_sol = compile_files(
        [CONTRACT_PATH], allow_paths=ALLOWED_PATHS, solc_version=SOLC_VERSION,
        optimize=True, optimize_runs=200, via_ir=True
    )
    contract_id, contract_interface = compiled_sol.popitem()
    print(f"✅ '{contract_id}' compiled successfully via IR.")
    return contract_interface


@pytest.fixture(scope="function")
def logic_contract(compiled_contract, w3_and_accounts):
    """为每个测试函数部署一个新的合约实例 (需要3个签名)"""
    w3, accounts = w3_and_accounts
    deployer = accounts[0]
    print("\nDeploying new contract instance for test (requiredSigs=3)...")
    initial_pks_data = [format_pk_for_contract(pk) for pk in oracle_pks]
    required_sigs = 3

    Contract = w3.eth.contract(abi=compiled_contract['abi'], bytecode=compiled_contract['bin'])
    tx_hash = Contract.constructor(initial_pks_data, required_sigs).transact({'from': deployer})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"Contract deployed at: {receipt['contractAddress']}")
    return w3.eth.contract(address=receipt['contractAddress'], abi=compiled_contract['abi'])


# --------------------------------------------------------------------
#  全面测试用例
# --------------------------------------------------------------------

def test_full_workflow_success(logic_contract, w3_and_accounts):
    """测试端到端的完整成功路径 (OrderCreated -> ProductionScheduled -> Shipped)"""
    print("\n--- Testing Full Workflow Success Path ---")
    w3, accounts = w3_and_accounts
    user = accounts[0]

    # 定义状态和事件的枚举值
    STATE_ORDER_CREATED = 0
    STATE_PRODUCTION_SCHEDULED = 1
    STATE_SHIPPED = 2
    EVENT_PAYMENT_RECEIVED = 0
    EVENT_MANUFACTURING_COMPLETE = 1

    signer_indices = [0, 1, 2]
    pks_mask = sum(1 << i for i in signer_indices)
    sks_to_use = [oracle_sks[i] for i in signer_indices]

    # --- 第一步: OrderCreated -> ProductionScheduled ---
    print("Step 1: Transitioning to ProductionScheduled...")
    nonce0_payload = encode_packed(['uint8', 'uint8', 'uint256'], [STATE_ORDER_CREATED, EVENT_PAYMENT_RECEIVED, 0])
    sigs0 = [sign(nonce0_payload, sk, domain=b"ILC") for sk in sks_to_use]
    agg_sig0 = format_sig_for_contract(aggregate_sigs(sigs0))

    tx_hash1 = logic_contract.functions.transition(EVENT_PAYMENT_RECEIVED, agg_sig0, pks_mask).transact({'from': user})
    receipt1 = w3.eth.wait_for_transaction_receipt(tx_hash1)
    assert receipt1.status == 1

    # 验证第一步转换后的状态
    logs1 = logic_contract.events.TransitionExecuted().get_logs(from_block=receipt1.blockNumber,
                                                                to_block=receipt1.blockNumber)
    assert logs1[0]['args']['to'] == STATE_PRODUCTION_SCHEDULED
    print("✅ Step 1 successful.")

    # --- 第二步: ProductionScheduled -> Shipped ---
    print("Step 2: Transitioning to Shipped...")
    # 注意：nonce 现在是 1，currentState 是 1
    nonce1_payload = encode_packed(['uint8', 'uint8', 'uint256'],
                                   [STATE_PRODUCTION_SCHEDULED, EVENT_MANUFACTURING_COMPLETE, 1])
    sigs1 = [sign(nonce1_payload, sk, domain=b"ILC") for sk in sks_to_use]
    agg_sig1 = format_sig_for_contract(aggregate_sigs(sigs1))

    tx_hash2 = logic_contract.functions.transition(EVENT_MANUFACTURING_COMPLETE, agg_sig1, pks_mask).transact(
        {'from': user})
    receipt2 = w3.eth.wait_for_transaction_receipt(tx_hash2)
    assert receipt2.status == 1

    # 验证第二步转换后的状态
    logs2 = logic_contract.events.TransitionExecuted().get_logs(from_block=receipt2.blockNumber,
                                                                to_block=receipt2.blockNumber)
    assert logs2[0]['args']['to'] == STATE_SHIPPED
    print("✅ Step 2 successful. Full workflow completed!")


def test_deadline_success_within_limit(logic_contract, w3_and_accounts):
    """测试在 deadline 期限内进行转换，应该成功"""
    print("\n--- Testing Deadline: Success within limit ---")
    w3, accounts = w3_and_accounts
    user = accounts[0]

    # --- 先完成第一步转换 ---
    tx_hash1 = logic_contract.functions.transition(0, format_sig_for_contract(aggregate_sigs(
        [sign(encode_packed(['uint8', 'uint8', 'uint256'], [0, 0, 0]), sk, domain=b"ILC") for sk in oracle_sks[:3]])),
                                                   7).transact({'from': user})
    receipt1 = w3.eth.wait_for_transaction_receipt(tx_hash1)
    assert receipt1.status == 1
    print("First transition completed.")

    # --- 时间旅行：快进1小时 (远小于72小时的deadline) ---
    ONE_HOUR = 3600
    increase_time(w3, ONE_HOUR)

    # --- 尝试进行第二步转换 ---
    print("Attempting second transition within deadline...")
    payload = encode_packed(['uint8', 'uint8', 'uint256'], [1, 1, 1])
    sigs = [sign(payload, sk, domain=b"ILC") for sk in oracle_sks[:3]]
    agg_sig = format_sig_for_contract(aggregate_sigs(sigs))

    tx_hash2 = logic_contract.functions.transition(1, agg_sig, 7).transact({'from': user})
    receipt2 = w3.eth.wait_for_transaction_receipt(tx_hash2)

    assert receipt2.status == 1, "Transition within deadline should succeed but failed"
    print("✅ PASSED: Transition within deadline was successful.")


def test_deadline_fail_after_limit(logic_contract, w3_and_accounts):
    """测试在 deadline 期限后进行转换，应该失败"""
    print("\n--- Testing Deadline: Failure after limit ---")
    w3, accounts = w3_and_accounts
    user = accounts[0]

    # --- 先完成第一步转换 ---
    tx_hash1 = logic_contract.functions.transition(0, format_sig_for_contract(aggregate_sigs(
        [sign(encode_packed(['uint8', 'uint8', 'uint256'], [0, 0, 0]), sk, domain=b"ILC") for sk in oracle_sks[:3]])),
                                                   7).transact({'from': user})
    receipt1 = w3.eth.wait_for_transaction_receipt(tx_hash1)
    assert receipt1.status == 1
    print("First transition completed.")

    # --- 时间旅行：快进72小时+1秒，以超过deadline ---
    DEADLINE_SECONDS = 72 * 3600
    increase_time(w3, DEADLINE_SECONDS + 1)

    # --- 尝试进行第二步转换 ---
    print("Attempting second transition after deadline...")
    payload = encode_packed(['uint8', 'uint8', 'uint256'], [1, 1, 1])
    sigs = [sign(payload, sk, domain=b"ILC") for sk in oracle_sks[:3]]
    agg_sig = format_sig_for_contract(aggregate_sigs(sigs))

    with pytest.raises(ContractLogicError, match="ILC: deadline passed"):
        logic_contract.functions.transition(1, agg_sig, 7).transact({'from': user})

    print("✅ PASSED: Transaction correctly reverted with 'ILC: deadline passed'.")