import pytest
import os
from web3 import Web3, HTTPProvider
from web3.exceptions import ContractLogicError
from solcx import compile_files, install_solc
from typing import List, Tuple
from eth_abi.packed import encode_packed

# --------------------------------------------------------------------
# 1. 导入和配置
# --------------------------------------------------------------------
from src.blocka2a.utils.bn256 import (
    sign, aggregate_sigs, SecretKey, PublicKey, Signature, multiply, G2
)

GANACHE_URL = "http://127.0.0.1:8545"
SOLC_VERSION = '0.8.23'  # 与您的合约 pragma 版本一致
_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_TEST_DIR, '..', '..'))
CONTRACT_PATH = os.path.join(_PROJECT_ROOT, 'contracts', 'main', 'AgentGovernanceContract.sol')
ALLOWED_PATHS = [os.path.join(_PROJECT_ROOT, 'contracts')]

# --- 测试数据 ---
# 使用固定的、可复现的密钥进行测试
oracle_sks = [SecretKey(i + 1) for i in range(5)]
oracle_pks = [multiply(G2, sk) for sk in oracle_sks]


# --------------------------------------------------------------------
# 辅助函数和 Fixtures
# --------------------------------------------------------------------
def format_pk_for_contract(pk: PublicKey) -> Tuple[int, int, int, int]:
    return (pk[0].coeffs[0].n, pk[0].coeffs[1].n, pk[1].coeffs[0].n, pk[1].coeffs[1].n)


def format_sig_for_contract(sig: Signature) -> Tuple[int, int]:
    return (sig[0].n, sig[1].n)


@pytest.fixture(scope="module")
def w3_and_accounts():
    w3 = Web3(HTTPProvider(GANACHE_URL))
    assert w3.is_connected()
    return w3, w3.eth.accounts


@pytest.fixture(scope="module")
def compiled_contract():
    """编译合约，整个测试会话只执行一次。"""
    print(f"\nInstalling and using solc version {SOLC_VERSION}...")
    install_solc(SOLC_VERSION)
    print("Compiling contracts with optimizer and via-IR enabled to fix 'Stack too deep'...")

    # 【最终的、真正的修正】在编译时启用 via_ir 和 optimizer
    compiled_sol = compile_files(
        [CONTRACT_PATH],
        allow_paths=ALLOWED_PATHS,
        solc_version=SOLC_VERSION,
        optimize=True,  # 启用优化器
        optimize_runs=200,  # 优化运行次数
        via_ir=True  # 启用IR编译管道以解决 "Stack too deep"
    )

    contract_id, contract_interface = compiled_sol.popitem()
    print(f"✅ '{contract_id}' compiled successfully via IR.")
    return contract_interface


@pytest.fixture(scope="function")
def agc_contract(compiled_contract, w3_and_accounts):
    """为每个测试函数部署一个新的合约实例。"""
    w3, accounts = w3_and_accounts
    deployer = accounts[0]
    print("\nDeploying new contract instance for test...")
    initial_pks_data = [format_pk_for_contract(pk) for pk in oracle_pks]
    Contract = w3.eth.contract(abi=compiled_contract['abi'], bytecode=compiled_contract['bin'])
    tx_hash = Contract.constructor(initial_pks_data).transact({'from': deployer})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"Contract deployed at: {receipt['contractAddress']}")
    return w3.eth.contract(address=receipt['contractAddress'], abi=compiled_contract['abi'])


@pytest.fixture(scope="function")
def registered_did_for_update(agc_contract, w3_and_accounts):
    """一个预先注册好的、用于更新测试的DID"""
    w3, accounts = w3_and_accounts
    user = accounts[1]
    did = "did:blocka2a:eeeeeeeeee"  # 10个'e'
    tx_hash = agc_contract.functions.register(
        did, w3.keccak(text="initial"), "cid_update", 3
    ).transact({'from': user})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    assert receipt.status == 1
    print("\n--- Prerequisite: DID 'did:blocka2a:eeeeeeeeee' registered for update tests ---")
    return did


# --------------------------------------------------------------------
#  UPDATE 函数签名测试
# --------------------------------------------------------------------

@pytest.mark.parametrize("signer_indices, pks_mask_desc", [
    ([0, 1, 2], "Exact number of signers (3)"),
    ([0, 1, 2, 3], "More than enough signers (4)"),
    ([0, 1, 2, 3, 4], "All signers (5)")
])
def test_update_success_cases(agc_contract, w3_and_accounts, registered_did_for_update, signer_indices, pks_mask_desc):
    """测试 update 成功的场景：签名数量满足或超过要求"""
    print(f"\n--- Testing UPDATE Success: {pks_mask_desc} ---")
    w3, accounts = w3_and_accounts
    user = accounts[1]
    did = registered_did_for_update

    new_doc_hash = w3.keccak(text="update_success")
    pks_mask = sum(1 << i for i in signer_indices)

    entry = agc_contract.functions._didEntries(did).call()
    payload = encode_packed(['string', 'bytes32', 'uint256'], [did, new_doc_hash, entry[1]])

    sks_to_use = [oracle_sks[i] for i in signer_indices]
    sigs = [sign(payload, sk, domain=b"AGC-update") for sk in sks_to_use]
    agg_sig = format_sig_for_contract(aggregate_sigs(sigs))

    tx_hash = agc_contract.functions.update(did, new_doc_hash, agg_sig, pks_mask).transact({'from': user})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    assert receipt.status == 1
    print(f"✅ PASSED: Update successful with {len(signer_indices)} signers.")
    updated_entry = agc_contract.functions._didEntries(did).call()
    assert updated_entry[2] == new_doc_hash


def test_update_fail_insufficient_signatures(agc_contract, w3_and_accounts, registered_did_for_update):
    """测试 update 失败的场景：签名数量不足"""
    print("\n--- Testing UPDATE Failure: Insufficient Signatures ---")
    w3, accounts = w3_and_accounts
    user = accounts[1]
    did = registered_did_for_update

    new_doc_hash = w3.keccak(text="update_fail")
    # DID需要3个签名，我们只提供2个
    signer_indices = [0, 1]
    pks_mask = sum(1 << i for i in signer_indices)

    entry = agc_contract.functions._didEntries(did).call()
    payload = encode_packed(['string', 'bytes32', 'uint256'], [did, new_doc_hash, entry[1]])

    sks_to_use = [oracle_sks[i] for i in signer_indices]
    sigs = [sign(payload, sk, domain=b"AGC-update") for sk in sks_to_use]
    agg_sig = format_sig_for_contract(aggregate_sigs(sigs))

    with pytest.raises(ContractLogicError, match="AGC: not enough signers"):
        agc_contract.functions.update(did, new_doc_hash, agg_sig, pks_mask).transact({'from': user})
    print("✅ PASSED: Transaction correctly reverted due to insufficient signers.")


def test_update_fail_bad_signature_wrong_payload(agc_contract, w3_and_accounts, registered_did_for_update):
    """测试 update 失败的场景：对错误的数据进行了签名"""
    print("\n--- Testing UPDATE Failure: Signature with Wrong Payload ---")
    w3, accounts = w3_and_accounts
    user = accounts[1]
    did = registered_did_for_update

    new_doc_hash = w3.keccak(text="update_fail_bad_sig")
    wrong_doc_hash = w3.keccak(text="THIS_IS_WRONG")
    signer_indices = [0, 1, 2]
    pks_mask = sum(1 << i for i in signer_indices)

    entry = agc_contract.functions._didEntries(did).call()
    payload = encode_packed(['string', 'bytes32', 'uint256'], [did, wrong_doc_hash, entry[1]])

    sks_to_use = [oracle_sks[i] for i in signer_indices]
    sigs = [sign(payload, sk, domain=b"AGC-update") for sk in sks_to_use]
    agg_sig = format_sig_for_contract(aggregate_sigs(sigs))

    with pytest.raises(ContractLogicError, match="AGC: aggregate signature verification failed"):
        agc_contract.functions.update(did, new_doc_hash, agg_sig, pks_mask).transact({'from': user})
    print("✅ PASSED: Transaction correctly reverted due to bad signature (wrong payload).")


def test_update_fail_replay_attack(agc_contract, w3_and_accounts, registered_did_for_update):
    """测试 update 失败的场景：重放攻击"""
    print("\n--- Testing UPDATE Failure: Replay Attack ---")
    w3, accounts = w3_and_accounts
    user = accounts[1]
    did = registered_did_for_update

    first_update_hash = w3.keccak(text="first_update_for_replay")
    signer_indices = [0, 1, 2]
    pks_mask = sum(1 << i for i in signer_indices)

    entry = agc_contract.functions._didEntries(did).call()
    payload = encode_packed(['string', 'bytes32', 'uint256'], [did, first_update_hash, entry[1]])

    sks_to_use = [oracle_sks[i] for i in signer_indices]
    sigs = [sign(payload, sk, domain=b"AGC-update") for sk in sks_to_use]
    good_agg_sig = format_sig_for_contract(aggregate_sigs(sigs))

    tx_hash = agc_contract.functions.update(did, first_update_hash, good_agg_sig, pks_mask).transact({'from': user})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    assert receipt.status == 1
    print("First update successful, version is now 2.")

    with pytest.raises(ContractLogicError, match="AGC: aggregate signature verification failed"):
        agc_contract.functions.update(did, first_update_hash, good_agg_sig, pks_mask).transact({'from': user})
    print("✅ PASSED: Replay attack correctly reverted.")


# --------------------------------------------------------------------
#  REVOKE 函数签名测试
# --------------------------------------------------------------------
@pytest.fixture(scope="function")
def registered_did_for_revoke(agc_contract, w3_and_accounts):
    """一个预先注册好的、用于撤销测试的DID"""
    w3, accounts = w3_and_accounts
    user = accounts[1]
    did = "did:blocka2a:deadbeef00"
    tx_hash = agc_contract.functions.register(
        did, w3.keccak(text="initial_revoke"), "cid_revoke", 2
    ).transact({'from': user})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    assert receipt.status == 1
    print("\n--- Prerequisite: DID 'did:blocka2a:deadbeef00' registered for revoke tests (req 2 sigs) ---")
    return did


def test_revoke_success(agc_contract, w3_and_accounts, registered_did_for_revoke):
    """测试 revoke 成功的场景"""
    print("\n--- Testing REVOKE Success ---")
    w3, accounts = w3_and_accounts
    user = accounts[1]
    did = registered_did_for_revoke

    signer_indices = [3, 4]
    pks_mask = sum(1 << i for i in signer_indices)

    entry = agc_contract.functions._didEntries(did).call()
    payload = encode_packed(['string', 'bytes32', 'uint256'], [did, b'\x00' * 32, entry[1]])

    sks_to_use = [oracle_sks[i] for i in signer_indices]
    sigs = [sign(payload, sk, domain=b"AGC-revoke") for sk in sks_to_use]
    agg_sig = format_sig_for_contract(aggregate_sigs(sigs))

    tx_hash = agc_contract.functions.revoke(did, agg_sig, pks_mask).transact({'from': user})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    assert receipt.status == 1

    revoked_entry = agc_contract.functions._didEntries(did).call()
    assert revoked_entry[4] == 1
    print("✅ PASSED: Revoke successful.")


def test_revoke_fail_wrong_domain(agc_contract, w3_and_accounts, registered_did_for_revoke):
    """测试 revoke 失败的场景：使用了错误的签名域 (domain)"""
    print("\n--- Testing REVOKE Failure: Wrong Signature Domain ---")
    w3, accounts = w3_and_accounts
    user = accounts[1]
    did = registered_did_for_revoke

    signer_indices = [0, 1]
    pks_mask = sum(1 << i for i in signer_indices)

    entry = agc_contract.functions._didEntries(did).call()
    payload = encode_packed(['string', 'bytes32', 'uint256'], [did, b'\x00' * 32, entry[1]])

    sks_to_use = [oracle_sks[i] for i in signer_indices]
    sigs = [sign(payload, sk, domain=b"AGC-update") for sk in sks_to_use]  # Wrong domain
    agg_sig = format_sig_for_contract(aggregate_sigs(sigs))

    with pytest.raises(ContractLogicError, match="AGC: aggregate signature verification failed"):
        agc_contract.functions.revoke(did, agg_sig, pks_mask).transact({'from': user})
    print("✅ PASSED: Transaction correctly reverted due to wrong signature domain.")


def test_fail_update_a_revoked_did(agc_contract, w3_and_accounts, registered_did_for_revoke):
    """测试对一个已撤销的DID进行任何操作都会失败"""
    print("\n--- Testing Failure: Operating on a Revoked DID ---")
    w3, accounts = w3_and_accounts
    user = accounts[1]
    did = registered_did_for_revoke

    signer_indices = [0, 1]
    pks_mask = sum(1 << i for i in signer_indices)
    entry = agc_contract.functions._didEntries(did).call()
    payload = encode_packed(['string', 'bytes32', 'uint256'], [did, b'\x00' * 32, entry[1]])
    sks_to_use = [oracle_sks[i] for i in signer_indices]
    sigs = [sign(payload, sk, domain=b"AGC-revoke") for sk in sks_to_use]
    agg_sig = format_sig_for_contract(aggregate_sigs(sigs))
    tx_hash = agc_contract.functions.revoke(did, agg_sig, pks_mask).transact({'from': user})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    assert receipt.status == 1
    print("DID successfully revoked.")

    with pytest.raises(ContractLogicError, match="AGC: DID not active"):
        new_doc_hash = w3.keccak(text="update_a_revoked_did")
        entry_after_revoke = agc_contract.functions._didEntries(did).call()
        update_payload = encode_packed(['string', 'bytes32', 'uint256'], [did, new_doc_hash, entry_after_revoke[1]])
        update_sigs = [sign(update_payload, sk, domain=b"AGC-update") for sk in sks_to_use]
        update_agg_sig = format_sig_for_contract(aggregate_sigs(update_sigs))
        agc_contract.functions.update(did, new_doc_hash, update_agg_sig, pks_mask).transact({'from': user})
    print("✅ PASSED: Update on a revoked DID correctly reverted.")

    with pytest.raises(ContractLogicError, match="AGC: DID not active"):
        agc_contract.functions.revoke(did, agg_sig, pks_mask).transact({'from': user})
    print("✅ PASSED: Revoke on a revoked DID correctly reverted.")