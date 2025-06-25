import os
import pytest
from web3 import Web3, HTTPProvider
from solcx import compile_files, install_solc, set_solc_version, link_code

RPC_URL      = "http://127.0.0.1:8545"
SOLC_VERSION = "0.8.20"

# 合约路径
ROOT         = os.path.abspath(os.path.join(__file__, "..", "..", ".."))
LIB_PATH     = os.path.join(ROOT, "contracts", "lib",  "EnvironmentalPolicyLogic.sol")
HARNESS_PATH = os.path.join(ROOT, "contracts", "main", "TestEnvironmentalHarness.sol")

# ---------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------
@pytest.fixture(scope="module")
def w3():
    w3 = Web3(HTTPProvider(RPC_URL))
    assert w3.is_connected()
    return w3

@pytest.fixture(scope="module")
def compiled():
    install_solc(SOLC_VERSION)
    set_solc_version(SOLC_VERSION)
    return compile_files(
        [LIB_PATH, HARNESS_PATH],
        allow_paths=[os.path.join(ROOT, "contracts")],
        solc_version=SOLC_VERSION
    )

@pytest.fixture
def harness_contract(compiled, w3):
    deployer = w3.eth.accounts[0]

    # 1. 拿到 ABI + bytecode
    lib_if     = compiled[f"{LIB_PATH}:EnvironmentalPolicyLogic"]
    harness_if = compiled[f"{HARNESS_PATH}:TestEnvironmentalHarness"]

    # 2. 部署库
    Lib = w3.eth.contract(abi=lib_if["abi"], bytecode=lib_if["bin"])
    tx  = Lib.constructor().transact({"from": deployer})
    lib_addr = w3.eth.wait_for_transaction_receipt(tx).contractAddress

    # 3. link code
    linked_bin = link_code(
        harness_if["bin"],
        {f"{LIB_PATH}:EnvironmentalPolicyLogic": lib_addr},
        solc_version=SOLC_VERSION
    )

    # 4. 部署 Harness
    Har = w3.eth.contract(abi=harness_if["abi"], bytecode=linked_bin)
    tx2 = Har.constructor().transact({"from": deployer})
    har_addr = w3.eth.wait_for_transaction_receipt(tx2).contractAddress

    return w3.eth.contract(address=har_addr, abi=harness_if["abi"])

# ---------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------
def test_low_below_low(harness_contract):
    # "low" <= LOW
    assert harness_contract.functions.testEvaluate("low", 0).call() is True

def test_medium_above_low(harness_contract):
    # "medium" > LOW
    assert harness_contract.functions.testEvaluate("medium", 0).call() is False

def test_medium_at_medium(harness_contract):
    # "medium" <= MEDIUM
    assert harness_contract.functions.testEvaluate("medium", 1).call() is True

def test_high_above_medium(harness_contract):
    # "high" > MEDIUM
    assert harness_contract.functions.testEvaluate("high", 1).call() is False

def test_high_at_high(harness_contract):
    # "high" <= HIGH
    assert harness_contract.functions.testEvaluate("high", 2).call() is True

def test_invalid_revert(harness_contract):
    # 非法字符串应 revert
    with pytest.raises(Exception):
        harness_contract.functions.testEvaluate("unknown", 2).call()
