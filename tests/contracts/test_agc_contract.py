import json
import os
import pytest
from web3 import Web3, HTTPProvider
from web3.exceptions import ContractLogicError
from solcx import compile_files, install_solc

from src.blocka2a.utils import bn256 as bls_bn256

# --- 配置 ---
GANACHE_URL = "http://127.0.0.1:8545"
SOLC_VERSION = '0.8.23'
_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_TEST_DIR, '..', '..'))
CONTRACT_PATH = os.path.join(_PROJECT_ROOT, 'contracts', 'main', 'AgentGovernanceContract.sol')
ALLOWED_PATHS = [os.path.join(_PROJECT_ROOT, 'contracts')]

# --- 测试数据 ---
oracle_sks = [
    bls_bn256.SecretKey(2833825224628770647255613288651483959178104459000430758204801703807178990217),
    bls_bn256.SecretKey(19020176885312313733264572853669371179783749614111895563810414749642828590597),
    bls_bn256.SecretKey(17209595577509179005721276854579044608748368966654267456114674148343750200167),
    bls_bn256.SecretKey(15552513599869556358546192840299715781861744391901239924434503987525011545606),
    bls_bn256.SecretKey(8283205931288848621696243456090300950392495072752410166429143470090943695348),
]


# --- 辅助函数 ---
def print_header(title): print("\n" + "=" * 70 + f"\n// {title.upper()}\n" + "=" * 70)


def deploy_contract(w3, contract_interface, deployer_account):
    print("Deploying contract with initial public keys...")
    initial_pks_data = [
        [7201262511018777420451623912981106805074895484287586479273509767667031020877,
         20627995582691274325938795393287500578829791078774336744819305859549221054247,
         17794544309597632664804340361278364484914857652765668401051331223281973265488,
         16428373389911722451866691214395631318837975390055736858258279478012471302068],
        [16434898235636967359907296089219646677434070620369214688456265912781365309740,
         20672905215967458025863051617247169375376474967764917936943384557269291631707,
         21082228425857990356657446562831270628394855211199455426641043315157773108500,
         6836206877332651390097084383609590185148303449902042757297653320094804212287],
        [9799171705170468065272349835531654635184539585297902249724341319010720592456,
         4583224473756412134598492934991320648693771207254682869740814743783417776115,
         10333586867519003804950951510402253133954594662645400621716312600463417762187,
         3387986602677557717495442587955363899785285107168820325512707677224587602421],
        [5159020562597402209428121078249167730088529356255454136598327015868231914806,
         20688083087888160286743136529691971779201342198606331628359833282625656020108,
         19028121209301892988000839473152200147897750033456956113172372269206363401876,
         10424726172542083659009102852390757309048665182873384172664112560956080117768],
        [10213554732849998790090689158401969308069776785180793695124967312334345756572,
         20712802657811935955414069141625701711122135244599603342802493798180707315723,
         13363941958492403586700552175411348053136024457768386857160623775844466087194,
         8298407620731997134278584413798174062700966781613970239543932432091190233924]
    ]
    tx_hash = w3.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin']).constructor(
        initial_pks_data).transact({'from': deployer_account})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    contract_address = receipt['contractAddress']
    print(f"Contract deployed at: {contract_address}")
    return w3.eth.contract(address=contract_address, abi=contract_interface['abi'])


# --- 主测试函数 ---

def test_agent_governance_contract():
    # 1. 设置
    print_header("Setup: Connecting to Blockchain & Compiling Contract")
    w3 = Web3(HTTPProvider(GANACHE_URL))
    assert w3.is_connected(), "Failed to connect to Ganache"
    print(f"Installing and using solc version {SOLC_VERSION}...")
    install_solc(SOLC_VERSION)
    print("Compiling contracts with optimizer and via-ir pipeline enabled...")
    compiled_sol = compile_files([CONTRACT_PATH], allow_paths=ALLOWED_PATHS, solc_version=SOLC_VERSION, optimize=True,
                                 optimize_runs=200, via_ir=True)
    contract_id, contract_interface = compiled_sol.popitem()
    print(f"'{contract_id}' compiled successfully.")

    # 2. 部署
    deployer = w3.eth.accounts[0]
    agc_contract = deploy_contract(w3, contract_interface, deployer)

    # 3. 测试注册
    print_header("Test 1: Register a new DID")
    test_did = "did:blocka2a:12345abcde"
    doc_content = {"@context": "https://www.w3.org/ns/did/v1", "id": test_did}
    doc_bytes = json.dumps(doc_content, sort_keys=True).encode('utf-8')
    doc_hash = w3.keccak(doc_bytes)
    test_cid = "QmRAQB6e4n9v2D4V4Abdeo4d23d"
    required_sigs = 3
    tx_hash = agc_contract.functions.register(test_did, doc_hash, test_cid, required_sigs).transact({'from': deployer})
    w3.eth.wait_for_transaction_receipt(tx_hash)
    print("DID registered successfully.")
    resolved_hash, resolved_cid = agc_contract.functions.resolve(test_did).call()
    assert resolved_hash == doc_hash and resolved_cid == test_cid
    print("✅ PASSED: DID registration and resolution verified.")

    # 4. 测试更新
    print_header("Test 2: Update a DID with an Aggregate Signature")
    new_doc_content = {"@context": "https://www.w3.org/ns/did/v1", "id": test_did, "version": 2}
    new_doc_bytes = json.dumps(new_doc_content, sort_keys=True).encode('utf-8')
    new_doc_hash = w3.keccak(new_doc_bytes)
    signer_indices = [0, 2, 4];
    pks_mask = (1 << 0) | (1 << 2) | (1 << 4)
    print(f"Signers (by index): {signer_indices}. Mask: {pks_mask}")
    did_entry = agc_contract.functions.getDIDEntry(test_did).call()
    current_version = did_entry[1]

    # 构造与链上 _hashToPoint 输入完全匹配的 message
    message_to_hash_update = test_did.encode('utf-8') + new_doc_hash + current_version.to_bytes(32, 'big')
    update_domain = agc_contract.functions.DST_UPDATE().call()

    participating_sks = [oracle_sks[i] for i in signer_indices]
    signatures = [bls_bn256.sign(message_to_hash_update, sk, domain=update_domain) for sk in participating_sks]
    agg_sig_point = bls_bn256.aggregate_sigs(signatures)
    agg_sig_formatted = [agg_sig_point[0].n, agg_sig_point[1].n]
    print("Aggregate signature prepared.")

    tx_hash = agc_contract.functions.update(test_did, new_doc_hash, agg_sig_formatted, pks_mask).transact(
        {'from': deployer, 'gas': 30000000})
    w3.eth.wait_for_transaction_receipt(tx_hash)
    print("Update transaction successful.")

    resolved_hash_after_update, _ = agc_contract.functions.resolve(test_did).call()
    assert resolved_hash_after_update == new_doc_hash
    print("✅ PASSED: DID update with aggregate signature verified.")

    # 5. 测试撤销
    print_header("Test 3: Revoke a DID")
    did_entry_before_revoke = agc_contract.functions.getDIDEntry(test_did).call()
    current_version_before_revoke = did_entry_before_revoke[1]

    revoke_domain = agc_contract.functions.DST_REVOKE().call()
    message_to_hash_revoke = test_did.encode('utf-8') + (b'\x00' * 32) + current_version_before_revoke.to_bytes(32,
                                                                                                                'big')

    revoke_signatures = [bls_bn256.sign(message_to_hash_revoke, sk, domain=revoke_domain) for sk in participating_sks]
    revoke_agg_sig_point = bls_bn256.aggregate_sigs(revoke_signatures)
    revoke_agg_sig_formatted = [revoke_agg_sig_point[0].n, revoke_agg_sig_point[1].n]

    tx_hash = agc_contract.functions.revoke(test_did, revoke_agg_sig_formatted, pks_mask).transact(
        {'from': deployer, 'gas': 30000000})
    w3.eth.wait_for_transaction_receipt(tx_hash)
    print("Revoke transaction successful.")

    with pytest.raises(ContractLogicError, match="DID not active"):
        agc_contract.functions.resolve(test_did).call()
    print("✅ PASSED: DID revocation verified (resolve correctly reverted).")