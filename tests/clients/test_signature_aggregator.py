import pytest
import web3

from src.blocka2a.clients.signature_aggregator import SignatureAggregator
from src.blocka2a.clients.errors import InvalidParameterError, ContractError
from src.blocka2a.clients.base_client import BaseClient
import src.blocka2a.utils.bn256 as bn256

# 捕获原始 _load_contract，以便在 test_init_invalid_address 时恢复
import src.blocka2a.clients.base_client as bc_mod
ORIGINAL_LOAD_CONTRACT = bc_mod.BaseClient._load_contract

# --- 全局 Stub fixtures (function-scoped) ----------------------------

@pytest.fixture(autouse=True)
def stub_base_client_init(monkeypatch):
    # 跳过 BaseClient.__init__（不初始化 self._w3、self._ipfs 等）
    monkeypatch.setattr(
        BaseClient,
        "__init__",
        lambda self, rpc_endpoint, private_key=None, ipfs_gateway=None, default_gas=None: None
    )

@pytest.fixture(autouse=True)
def stub_aggregate_sigs(monkeypatch):
    # Stub 聚合算法，返回固定的 DummyFQ(1), DummyFQ(2)
    class DummyFQ:
        def __init__(self, n): self.n = n
    monkeypatch.setattr(
        bn256,
        "aggregate_sigs",
        lambda sigs: (DummyFQ(1), DummyFQ(2))
    )

@pytest.fixture(autouse=True)
def stub_send_tx(monkeypatch):
    # Stub 链上发送 tx，总是返回 b"\x11"*32
    monkeypatch.setattr(
        BaseClient,
        "_send_tx",
        lambda self, fn, *args: b"\x11" * 32
    )

@pytest.fixture
def stub_load_contract(monkeypatch):
    # 按需 Stub _load_contract，返回一个有 .functions.update 的假合约
    class FakeContract:
        def __init__(self):
            self.functions = type("F", (), {"update": lambda *args, **kwargs: None})
    monkeypatch.setattr(
        BaseClient,
        "_load_contract",
        lambda self, getter, addr: FakeContract()
    )

# --- 单元测试 ------------------------------------------------------------

def test_aggregate_empty_list_raises():
    with pytest.raises(InvalidParameterError):
        SignatureAggregator.aggregate([])

def test_aggregate_invalid_length_signature():
    with pytest.raises(InvalidParameterError):
        SignatureAggregator.aggregate([b"\x00" * 10])

def test_aggregate_success():
    sig1 = (5).to_bytes(32, "big") + (6).to_bytes(32, "big")
    sig2 = (7).to_bytes(32, "big") + (8).to_bytes(32, "big")
    agg = SignatureAggregator.aggregate([sig1, sig2])
    assert isinstance(agg, bytes) and len(agg) == 64
    # 根据 stub 返回的 DummyFQ(1), DummyFQ(2)
    assert agg == (1).to_bytes(32, "big") + (2).to_bytes(32, "big")

def test_bls_signature_to_uint256x2_invalid_length():
    with pytest.raises(InvalidParameterError):
        SignatureAggregator.bls_signature_to_uint256x2(b"\x00" * 10)

def test_bls_signature_to_uint256x2_success():
    x = 0x1234
    y = 0x5678
    sig = x.to_bytes(32, "big") + y.to_bytes(32, "big")
    out = SignatureAggregator.bls_signature_to_uint256x2(sig)
    assert out == [x, y]

# 加入 stub_load_contract 以避开 __init__ 中的 _load_contract 调用
def test_submit_task_validation_invalid_sig(stub_load_contract):
    aggregator = SignatureAggregator(
        rpc_endpoint="rpc",
        data_anchoring_address="0x" + "1" * 40
    )
    data_hash = b"\x01" * 32
    with pytest.raises(InvalidParameterError):
        aggregator.submit_task_validation(b"", data_hash, "ms", ["did:1"])

def test_submit_task_validation_success(stub_load_contract):
    aggregator = SignatureAggregator(
        rpc_endpoint="rpc",
        data_anchoring_address="0x" + "2" * 40
    )
    x, y = 9, 10
    agg_sig = x.to_bytes(32, "big") + y.to_bytes(32, "big")
    data_hash = b"\x02" * 32
    tx = aggregator.submit_task_validation(agg_sig, data_hash, "ms", ["didA", "didB"])
    assert tx == b"\x11" * 32

def test_submit_task_validation_onchain_error(monkeypatch, stub_load_contract):
    # 让 _send_tx 抛异常
    monkeypatch.setattr(
        BaseClient,
        "_send_tx",
        lambda self, fn, *args: (_ for _ in ()).throw(Exception("tx failure"))
    )
    aggregator = SignatureAggregator(
        rpc_endpoint="rpc",
        data_anchoring_address="0x" + "3" * 40
    )
    sig = (1).to_bytes(32, "big") + (2).to_bytes(32, "big")
    data_hash = b"\x03" * 32
    with pytest.raises(ContractError):
        aggregator.submit_task_validation(sig, data_hash, "ms", ["didX"])

def test_init_invalid_address(monkeypatch):
    # 恢复原始 _load_contract
    monkeypatch.setattr(BaseClient, "_load_contract", ORIGINAL_LOAD_CONTRACT)
    # 继续跳过 BaseClient.__init__
    monkeypatch.setattr(
        BaseClient,
        "__init__",
        lambda self, rpc_endpoint, private_key=None, ipfs_gateway=None, default_gas=None: None
    )
    # 强制 Web3.is_address 返回 False
    monkeypatch.setattr(web3.Web3, "is_address", staticmethod(lambda addr: False))

    with pytest.raises(InvalidParameterError) as exc:
        SignatureAggregator(rpc_endpoint="rpc", data_anchoring_address="invalid_addr")
    assert "Invalid contract address" in str(exc.value)
