# tests/contracts/test_temporal_policy.py
import os
import pytest
from web3 import Web3, HTTPProvider
from solcx import compile_files, install_solc, set_solc_version, link_code
from eth_utils import to_hex
from pathlib import Path

RPC_URL      = "http://127.0.0.1:8545"
SOLC_VERSION = "0.8.20"
ROOT         = os.path.abspath(os.path.join(__file__, "..", "..", ".."))
# HARNESS      = os.path.join(ROOT, "contracts", "main", "TestTemporalHarness.sol")
# LIB          = os.path.join(ROOT, "contracts", "lib",  "TemporalPolicyLogic.sol")
HARNESS = 'contracts/main/TestTemporalHarness.sol'
LIB     = 'contracts/lib/TemporalPolicyLogic.sol'

ONE_HOUR = 3600
ONE_DAY  = 86400
NINE_AM  = 9  * ONE_HOUR     #  32400
FIVE_PM  = 17 * ONE_HOUR     #  61200


# -------------------------------------------------------------------
# helpers
# -------------------------------------------------------------------
def set_block_timestamp(w3: Web3, ts: int) -> None:
    """Ganache/Anvil 只能“向未来”跳; 若目标≤当前块，则 +1 秒。"""
    latest = w3.eth.get_block("latest").timestamp
    if ts <= latest:
        ts = latest + 1
    w3.provider.make_request("evm_setNextBlockTimestamp", [to_hex(ts)])
    w3.provider.make_request("evm_mine", [])


def next_day_at(base_ts: int, seconds_after_midnight: int) -> int:
    """返回“明天 00:00 + offset”的绝对时间戳 (保证 > base_ts)。"""
    return ((base_ts // ONE_DAY) + 1) * ONE_DAY + seconds_after_midnight


# -------------------------------------------------------------------
# fixtures
# -------------------------------------------------------------------
@pytest.fixture(scope="module")
def w3_and_accounts():
    w3 = Web3(HTTPProvider(RPC_URL))
    assert w3.is_connected()
    return w3, w3.eth.accounts


@pytest.fixture(scope="module")
def compiled():
    install_solc(SOLC_VERSION)
    set_solc_version(SOLC_VERSION)
    return compile_files([HARNESS, LIB],
                         allow_paths=[os.path.join(ROOT, "contracts")],
                         solc_version=SOLC_VERSION)

# @pytest.fixture(scope="module")
# def compiled():
#     artifacts_dir = Path(ROOT) / "artifacts"
#     artifacts_dir.mkdir(exist_ok=True)  # 确保目录存在
    
#     return compile_files(
#         [HARNESS, LIB],
#         allow_paths=[os.path.join(ROOT, "contracts")],
#         solc_version=SOLC_VERSION,
#         output_dir=str(artifacts_dir),  # 关键：指定输出目录
#         via_ir=True,
#         optimize=True
#     )


@pytest.fixture
def harness(compiled, w3_and_accounts):
    w3, accs  = w3_and_accounts
    deployer  = accs[0]

    lib_if    = compiled[f"{LIB}:TemporalPolicyLogic"]
    har_if    = compiled[f"{HARNESS}:TestTemporalHarness"]

    # 1. deploy library
    Lib = w3.eth.contract(abi=lib_if["abi"], bytecode=lib_if["bin"])
    lib_addr = w3.eth.wait_for_transaction_receipt(
        Lib.constructor().transact({"from": deployer})
    ).contractAddress

    # 2. link & deploy harness
    linked_bin = link_code(
        har_if["bin"],
        {f"{LIB}:TemporalPolicyLogic": lib_addr},
        solc_version=SOLC_VERSION,
    )
    Har = w3.eth.contract(abi=har_if["abi"], bytecode=linked_bin)
    har_addr = w3.eth.wait_for_transaction_receipt(
        Har.constructor().transact({"from": deployer})
    ).contractAddress

    return w3.eth.contract(address=har_addr, abi=har_if["abi"])


# -------------------------------------------------------------------
# tests
# -------------------------------------------------------------------
def test_absolute_window_success(harness, w3_and_accounts):
    w3, _ = w3_and_accounts
    now   = w3.eth.get_block("latest").timestamp
    set_block_timestamp(w3, now + 5)          # 保证 block.timestamp == now+5
    blk   = w3.eth.get_block("latest").timestamp
    params = (blk - ONE_HOUR, blk + ONE_HOUR, 0, 0)
    assert harness.functions.testEvaluate(params).call() is True


def test_absolute_window_fail_before(harness, w3_and_accounts):
    w3, _ = w3_and_accounts
    now   = w3.eth.get_block("latest").timestamp
    valid_after = now + 2 * ONE_HOUR
    set_block_timestamp(w3, now + ONE_HOUR)   # 还没到 valid_after
    params = (valid_after, valid_after + ONE_HOUR, 0, 0)
    assert harness.functions.testEvaluate(params).call() is False


def test_absolute_window_fail_after(harness, w3_and_accounts):
    w3, _ = w3_and_accounts
    now   = w3.eth.get_block("latest").timestamp
    valid_before = now + ONE_HOUR
    set_block_timestamp(w3, valid_before + ONE_HOUR)   # 超出窗口
    params = (now, valid_before, 0, 0)
    assert harness.functions.testEvaluate(params).call() is False


def test_daily_window_success(harness, w3_and_accounts):
    w3, _ = w3_and_accounts
    base  = w3.eth.get_block("latest").timestamp
    noon  = next_day_at(base, 12 * ONE_HOUR)
    set_block_timestamp(w3, noon)
    params = (0, noon + 10 * 365 * ONE_DAY, NINE_AM, FIVE_PM)
    assert harness.functions.testEvaluate(params).call() is True


def test_daily_window_fail_before(harness, w3_and_accounts):
    w3, _ = w3_and_accounts
    base  = w3.eth.get_block("latest").timestamp
    eight = next_day_at(base, 8 * ONE_HOUR)   # 08:00 < 09:00
    set_block_timestamp(w3, eight)
    params = (0, eight + 10 * 365 * ONE_DAY, NINE_AM, FIVE_PM)
    assert harness.functions.testEvaluate(params).call() is False


def test_daily_window_fail_after(harness, w3_and_accounts):
    w3, _ = w3_and_accounts
    base  = w3.eth.get_block("latest").timestamp
    six   = next_day_at(base, 18 * ONE_HOUR)  # 18:00 > 17:00
    set_block_timestamp(w3, six)
    params = (0, six + 10 * 365 * ONE_DAY, NINE_AM, FIVE_PM)
    assert harness.functions.testEvaluate(params).call() is False
