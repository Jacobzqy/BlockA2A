import pytest
import json

from src.blocka2a.clients.task_initiator import TaskInitiator
from src.blocka2a.clients.base_client import BaseClient
from src.blocka2a.clients.errors import InvalidParameterError, NetworkError, ContractError

# --- Monkeypatch TaskMetadata to be serializable --------------------------------
@pytest.fixture(autouse=True)
def patch_taskmetadata(monkeypatch):
    import src.blocka2a.clients.task_initiator as ti_mod
    # Make TaskMetadata simply return a dict so json.dumps works
    monkeypatch.setattr(ti_mod, "TaskMetadata", lambda **kwargs: kwargs)

# --- Helpers & Fixtures --------------------------------------------------------

class FakeIPFS:
    def __init__(self):
        self.last_json = None

    def add_json(self, json_str):
        self.last_json = json_str
        return "fakecid"

class FakeFuncs:
    def anchor(self, data_hash, cid, deadline, status):
        # placeholder for function call object
        return "function_call"

class FakeContract:
    def __init__(self):
        self.functions = FakeFuncs()

@pytest.fixture(autouse=True)
def stub_base_client_init(monkeypatch):
    # Stub out BaseClient.__init__ to avoid real RPC/IPFS setup
    monkeypatch.setattr(
        BaseClient,
        "__init__",
        lambda self, rpc_endpoint, private_key=None, ipfs_gateway=None, default_gas=None: None
    )

@pytest.fixture
def fake_contract(monkeypatch):
    # Stub TaskInitiator._load_contract to return our fake contract
    monkeypatch.setattr(
        TaskInitiator,
        "_load_contract",
        lambda self, func, addr: FakeContract()
    )
    return FakeContract()

@pytest.fixture
def fake_send_tx(monkeypatch):
    # Stub _send_tx to return a fake tx hash
    monkeypatch.setattr(
        BaseClient,
        "_send_tx",
        lambda self, fn, *args: "0xfaketxhash"
    )
    return None

# --- Tests --------------------------------------------------------------------

def test_init_without_did_raises():
    with pytest.raises(InvalidParameterError):
        TaskInitiator("rpc_endpoint", "", "0xContractAddr")


def test_initiate_task_success(fake_contract, fake_send_tx):
    ti = TaskInitiator("rpc", "did:example:123", "0xabc")
    ti._ipfs = FakeIPFS()

    cid, tx_hash, data_hash = ti.initiate_task(
        participants=["p1", "p2"],
        description="A sample task",
        deadline=9876543210
    )

    assert cid == "fakecid"
    assert tx_hash == "0xfaketxhash"

    expected_meta = {
        "deadline": 9876543210,
        "description": "A sample task",
        "initiator": "did:example:123",
        "participants": ["p1", "p2"],
    }
    expected_json = json.dumps(expected_meta, separators=(",","\:"), sort_keys=True)
