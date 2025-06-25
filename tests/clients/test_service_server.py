import pytest
from types import SimpleNamespace

from src.blocka2a.clients.service_server import ServiceServer
from src.blocka2a.clients.base_client import BaseClient
from src.blocka2a.clients.errors import ContractError, IdentityError, InvalidParameterError
from web3 import Web3

# --- Fixtures ---------------------------------------------------------------

@pytest.fixture(autouse=True)
def stub_base_client_and_load(monkeypatch):
    # Stub BaseClient.__init__ to avoid real Web3/IPFS setup
    monkeypatch.setattr(
        BaseClient,
        "__init__",
        lambda self, *, rpc_endpoint, private_key, ipfs_gateway=None, default_gas=2_000_000: None
    )
    # Stub _load_contract to do nothing
    monkeypatch.setattr(
        ServiceServer,
        "_load_contract",
        lambda self, getter, addr: None
    )
    return None

class FakeVerifyCall:
    def __init__(self, return_value=True, raise_exc=None):
        self.return_value = return_value
        self.raise_exc = raise_exc
    def call(self):
        if self.raise_exc:
            raise self.raise_exc
        return self.return_value

class FakeFuncs:
    def __init__(self, verify_ret=True, verify_exc=None):
        self._verify_ret = verify_ret
        self._verify_exc = verify_exc
    def verifyTokenHash(self, token_hash):
        return FakeVerifyCall(self._verify_ret, self._verify_exc)
    def registerPolicy(self, params):
        return "reg_call"
    def removePolicy(self, params):
        return "rem_call"

class FakeACC:
    def __init__(self, verify_ret=True, verify_exc=None):
        self.functions = FakeFuncs(verify_ret, verify_exc)

@pytest.fixture
def fake_tx(monkeypatch):
    # Stub send_tx to return a fake tx hash
    monkeypatch.setattr(
        BaseClient,
        "_send_tx",
        lambda self, fn, *args: b"0xfaketx"
    )
    return None

# --- Tests for register_action ---------------------------------------------

def test_register_action():
    srv = ServiceServer(rpc_endpoint="rpc", acc_address="0xabc", private_key="key", resource_identifier="res")
    # first time True, second False
    assert srv.register_action("act1") is True
    assert srv.register_action("act1") is False

# --- Tests for get_token_hash ---------------------------------------------

def test_get_token_hash(monkeypatch):
    # stub solidity_keccak
    called = {}
    def fake_keccak(types, values):
        called['types'] = types
        called['values'] = values
        return b"hashbytes"
    monkeypatch.setattr(Web3, "solidity_keccak", fake_keccak)

    token = SimpleNamespace(
        agentDID="did:123",
        actionIdentifier="act",
        resourceIdentifier="res",
        expiry="999"
    )
    h = ServiceServer.get_token_hash(token)
    assert h == b"hashbytes"
    # verify parameters passed
    assert called['types'][0] == 'string'
    assert '|' in called['values']

# --- Tests for verify_token -----------------------------------------------

def test_verify_token_resource_mismatch():
    srv = ServiceServer(rpc_endpoint="rpc", acc_address="0xabc", private_key="key", resource_identifier="res")
    # token as dict
    token = {'resourceIdentifier': 'wrong', 'actionIdentifier': 'a'}
    assert srv.verify_token(token) is False


def test_verify_token_action_not_registered(monkeypatch):
    srv = ServiceServer(rpc_endpoint="rpc", acc_address="0xabc", private_key="key", resource_identifier="res")
    token = {'resourceIdentifier': 'res', 'actionIdentifier': 'act'}
    # no registration
    assert srv.verify_token(token) is False


def test_verify_token_success_and_failure(monkeypatch):
    srv = ServiceServer(rpc_endpoint="rpc", acc_address="0xabc", private_key="key", resource_identifier="res")
    # register action
    srv._registered_actions.add("act")
    # stub get_token_hash
    monkeypatch.setattr(ServiceServer, "get_token_hash", lambda cls, t: b"h")
    # stub _acct.functions
    srv._acct = FakeACC(verify_ret=True)
    token = {'resourceIdentifier': 'res', 'actionIdentifier': 'act'}
    assert srv.verify_token(token) is True
    # simulate contract error
    srv._acct = FakeACC(verify_exc=Exception("fail"))
    with pytest.raises(ContractError) as exc:
        srv.verify_token(token)
    assert "verifyTokenHash contract call failed" in str(exc.value)

# --- Tests for register_policy --------------------------------------------

def test_register_policy_identity_error():
    srv = ServiceServer(rpc_endpoint="rpc", acc_address="0xabc", private_key=None, resource_identifier="res")
    srv._acct = None
    with pytest.raises(IdentityError):
        srv.register_policy("a", SimpleNamespace(policy_type="t", policy_param="p"), [1,2,3], 0)


def test_register_policy_invalid_action(fake_tx):
    srv = ServiceServer(rpc_endpoint="rpc", acc_address="0xabc", private_key="key", resource_identifier="res")
    srv._acct = FakeACC()
    # not registered
    with pytest.raises(InvalidParameterError):
        srv.register_policy("act", SimpleNamespace(policy_type="t", policy_param="p"), [], 0)


def test_register_policy_success_and_failure(fake_tx, monkeypatch):
    srv = ServiceServer(rpc_endpoint="rpc", acc_address="0xabc", private_key="key", resource_identifier="res")
    srv._acct = object()
    srv._acc = FakeACC()
    srv._registered_actions.add("act")
    # success
    tx = srv.register_policy("act", SimpleNamespace(policy_type="t", policy_param="p"), [1], 1)
    assert tx == b"0xfaketx"
    # failure
    monkeypatch.setattr(BaseClient, "_send_tx", lambda self, fn, *args: (_ for _ in ()).throw(Exception("txfail")))
    with pytest.raises(ContractError) as exc:
        srv.register_policy("act", SimpleNamespace(policy_type="t", policy_param="p"), [1], 1)
    assert "registerPolicy transaction failed: txfail" in str(exc.value)

# --- Tests for remove_policy ---------------------------------------------

def test_remove_policy_identity_error():
    srv = ServiceServer(rpc_endpoint="rpc", acc_address="0xabc", private_key=None, resource_identifier="res")
    srv._acct = None
    with pytest.raises(IdentityError):
        srv.remove_policy("a", SimpleNamespace(policy_type="t", policy_param="p"), [1], 0)


def test_remove_policy_invalid_action(fake_tx):
    srv = ServiceServer(rpc_endpoint="rpc", acc_address="0xabc", private_key="key", resource_identifier="res")
    srv._acct = FakeACC()
    with pytest.raises(InvalidParameterError):
        srv.remove_policy("act", SimpleNamespace(policy_type="t", policy_param="p"), [], 0)


def test_remove_policy_success_and_failure(fake_tx, monkeypatch):
    srv = ServiceServer(rpc_endpoint="rpc", acc_address="0xabc", private_key="key", resource_identifier="res")
    srv._acct = object()
    srv._acc = FakeACC()
    srv._registered_actions.add("act")
    # success
    tx = srv.remove_policy("act", SimpleNamespace(policy_type="t", policy_param="p"), [1], 1)
    assert tx == b"0xfaketx"
    # failure
    monkeypatch.setattr(BaseClient, "_send_tx", lambda self, fn, *args: (_ for _ in ()).throw(Exception("fail")))
    with pytest.raises(ContractError) as exc:
        srv.remove_policy("act", SimpleNamespace(policy_type="t", policy_param="p"), [1], 1)
    assert "removePolicy transaction failed: fail" in str(exc.value)
