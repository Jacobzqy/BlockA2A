import pytest

from src.blocka2a.clients.base_client import BaseClient
from src.blocka2a.clients.errors import UnauthorizedError, TransactionError, InvalidParameterError
from web3.types import TxParams
from web3 import Web3


# --- Fixtures ---------------------------------------------------------------

@pytest.fixture
def stub_init(monkeypatch):
    """Stub out BaseClient.__init__ to avoid real Web3/IPFS setup"""
    monkeypatch.setattr(
        BaseClient,
        "__init__",
        lambda self, *, rpc_endpoint, private_key, ipfs_gateway, default_gas=2_000_000: None
    )
    return None


# --- Tests for __init__ -----------------------------------------------------

def test_init_empty_rpc_raises():
    """If rpc_endpoint is empty, __init__ should raise ValueError"""
    with pytest.raises(ValueError):
        BaseClient(rpc_endpoint="", private_key=None, ipfs_gateway=None)


# --- Tests for _load_contract -----------------------------------------------

def test_load_contract_invalid_address(stub_init):
    """Invalid Ethereum address should raise InvalidParameterError"""
    client = BaseClient(rpc_endpoint="rpc", private_key=None, ipfs_gateway=None)
    with pytest.raises(InvalidParameterError) as exc:
        client._load_contract(lambda w3, addr: None, "not_an_address")
    assert "Invalid contract address" in str(exc.value)


# --- Tests for _send_tx ----------------------------------------------------

class DummyFunc:
    """Mimics a contract function builder"""

    def __call__(self, *args):
        return self

    def build_transaction(self, tx_params: TxParams):
        # Return a dummy unsigned tx dict
        return {"to": "0x123", "data": "0x"}


class FakeAccount:
    address = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

    def sign_transaction(self, tx_dict):
        # Return a tuple where index 0 is raw tx bytes
        return (b"0xrawtx",)


class FakeEth:
    def __init__(self):
        self._nonce = 7

    def get_transaction_count(self, address):
        return self._nonce

    def send_raw_transaction(self, raw_tx):
        # Return a fake tx hash bytes
        return b"" * 32

    def wait_for_transaction_receipt(self, tx_hash, timeout):
        # Default success receipt
        return {"status": 1, "transactionHash": tx_hash}
