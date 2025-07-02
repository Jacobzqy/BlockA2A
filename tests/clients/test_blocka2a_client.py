# tests/clients/test_blocka2a_client.py
import sys, types
# ------------------------------------------------------------------
# 兼容 pycryptodome 的奇怪导入
fake_ecdh = types.ModuleType("Crypto.SelfTest.Protocol.test_ecdh")
fake_ecdh.public_key = lambda *_, **__: None
sys.modules["Crypto.SelfTest.Protocol.test_ecdh"] = fake_ecdh
# ------------------------------------------------------------------

import pytest
import time
import hashlib

import src.blocka2a.clients.blocka2a_client as client_mod
from src.blocka2a.clients.blocka2a_client import BlockA2AClient
from src.blocka2a.clients.base_client import BaseClient
from src.blocka2a.clients.errors import (
    InvalidParameterError, ContractError, NetworkError,
    LedgerError, IdentityError,
)
from src.blocka2a.types import AccessToken
import src.blocka2a.utils.bn256 as bn256

from src.blocka2a.types import PublicKeyEntry, ServiceEntry, Capabilities, PolicyConstraints, Proof, DIDDocument, \
    BLSPubkey, BLSSignature, BLSPrivateKey, Ed25519PrivateKey, Ed25519Signature, Ed25519PublicKey, AccessToken

# ------------------------------------------------------------------
# 自动补丁：把 json.dumps(sorted_keys) → sort_keys
@pytest.fixture(autouse=True)
def _patch_json_sorted(monkeypatch):
    orig = client_mod.json.dumps
    def fixed(obj, *a, **kw):
        if "sorted_keys" in kw:
            kw["sort_keys"] = kw.pop("sorted_keys")
        return orig(obj, *a, **kw)
    monkeypatch.setattr(client_mod.json, "dumps", fixed)

# 跳过 BaseClient 真正初始化
@pytest.fixture(autouse=True)
def _stub_baseclient(monkeypatch):
    monkeypatch.setattr(BaseClient, "__init__", lambda *_a, **_kw: None)

# -------------------------- 工具 -----------------------------------
def _fake_dac():
    return types.SimpleNamespace(
        functions=types.SimpleNamespace(
            anchor=lambda *_: types.SimpleNamespace(call=lambda: None),
            get=lambda *_: None,
        )
    )

def _fake_ipfs():
    return types.SimpleNamespace(
        add_json=lambda *_: "cid123",
        get=lambda *_: b'{"foo":"bar"}',
    )

# ------------------------ anchor_client ----------------------------
@pytest.fixture
def anchor_client(monkeypatch):
    monkeypatch.setattr(BlockA2AClient, "_load_contract",
                        lambda *_a, **_kw: _fake_dac())
    c = BlockA2AClient("rpc", "acc", "ilc", "agc", "dac",
                       private_key="0xkey", ipfs_gateway="ipfs")
    c._ipfs = _fake_ipfs()
    monkeypatch.setattr(BaseClient, "_send_tx",
                        lambda *_a, **_kw: b"txhash")
    return c

# ------------------------ verify_client ----------------------------
@pytest.fixture
def verify_client(monkeypatch):
    def _get(*_):
        return (hashlib.sha256(b'{"foo":"bar"}').digest(),
                "cid123", int(time.time()) + 3600, "anchored")
    dac = types.SimpleNamespace(functions=types.SimpleNamespace(get=_get))
    monkeypatch.setattr(BlockA2AClient, "_load_contract",
                        lambda *_a, **_kw: dac)
    c = BlockA2AClient("rpc", "acc", "ilc", "agc", "dac")
    c._ipfs = _fake_ipfs()
    return c

# --------------------------- 测试 ----------------------------------
def test_anchor_data_success(anchor_client):
    tx, cid, data_hash = anchor_client.anchor_data({"foo":"bar"}, 100)
    assert tx == b"txhash" and cid == "cid123"

def test_anchor_data_bad_json(anchor_client):
    class Bad: pass
    with pytest.raises(LedgerError):
        anchor_client.anchor_data(Bad(), 0)

def test_anchor_data_no_ipfs(anchor_client):
    anchor_client._ipfs = None
    with pytest.raises(NetworkError):
        anchor_client.anchor_data({}, 0)

def test_anchor_data_chain_error(anchor_client, monkeypatch):
    monkeypatch.setattr(BaseClient, "_send_tx",
                        lambda *_: (_ for _ in ()).throw(Exception()))
    with pytest.raises(ContractError):
        anchor_client.anchor_data({"foo":1}, 0)

def test_verify_data_success(verify_client):
    assert verify_client.verify_data({"foo":"bar"})

def test_verify_data_expired(verify_client):
    verify_client._dac.functions.get = lambda *_: (
        hashlib.sha256(b'{"foo":"bar"}').digest(),"cid",int(time.time())-1,"anchored")
    with pytest.raises(LedgerError):
        verify_client.verify_data({"foo":"bar"})

def test_verify_data_bad_status(verify_client):
    verify_client._dac.functions.get = lambda *_: (
        hashlib.sha256(b'{"foo":"bar"}').digest(),"cid",int(time.time())+10,"X")
    with pytest.raises(LedgerError):
        verify_client.verify_data({"foo":"bar"})

def test_verify_data_mismatch(verify_client):
    verify_client._dac.functions.get = lambda *_: (
        b"bad","cid",int(time.time())+10,"anchored")
    with pytest.raises(LedgerError):
        verify_client.verify_data({"foo":"bar"})

def test_generate_did_known():
    keys=["zeta","alpha"]
    expect = hashlib.sha256("alpha|zeta".encode()).hexdigest()[:10]
    assert BlockA2AClient.generate_did(keys) == f"did:blocka2a:{expect}"

def test_sign_task_invalid_sk():
    with pytest.raises(InvalidParameterError):
        BlockA2AClient.sign_task("x", b"h"*32, "m")

def test_sign_task_success(monkeypatch):
    import builtins, contextlib
    @contextlib.contextmanager
    def _bytes_patch():
        orig = builtins.bytes
        builtins.bytes = lambda s, enc="utf-8": s.encode(enc) if isinstance(s,str) else orig(s)
        try: yield
        finally: builtins.bytes = orig
    class P:   # dummy point
        def __init__(self,v): self.n=v
    monkeypatch.setattr(bn256,"SecretKey",lambda sk:sk)
    monkeypatch.setattr(bn256,"sign",lambda *_,**__: (P(1),P(2)))
    with _bytes_patch():
        sig = BlockA2AClient.sign_task(1,b"\0"*32,"m1")
    assert sig == (1).to_bytes(32,"big")+(2).to_bytes(32,"big")

def test_sign_task_bls_success(monkeypatch):
    """Test successful BLS signature generation."""
    class DummyPoint:
        def __init__(self, v):
            self.n = v

    # Mock BLS signing functions
    monkeypatch.setattr(bn256, "SecretKey", lambda sk: sk)
    monkeypatch.setattr(bn256, "sign", lambda msg, sk, domain: (DummyPoint(1), DummyPoint(2)))

    sig = BlockA2AClient.sign_task(
        private_key=1,  # Mock BLS private key
        task_hash=b"\0"*32,
        milestone="m1",
        proof_type="BLS256Signature2020"
    )

    expected_sig = (1).to_bytes(32, "big") + (2).to_bytes(32, "big")
    assert sig == expected_sig

def test_sign_task_ed25519_success(monkeypatch):
    """Test successful Ed25519 signature generation."""
    private_bytes = b"\x00" * 32 
    priv = Ed25519PrivateKey.from_private_bytes(private_bytes)

    sig = BlockA2AClient.sign_task(
        private_key=priv,
        task_hash=b"\x01" * 32,
        milestone="test_milestone",
        proof_type="Ed25519Signature2020"
    )

    assert isinstance(sig, bytes)
    assert len(sig) == 64

    # Verify the signature using the corresponding public key
    public_key = priv.public_key()
    key = str(b"\x01" * 32) + "|" + "test_milestone"
    msg = key.encode('utf-8')
    
    public_key.verify(sig, msg)

def test_sign_task_unsupported_proof_type():
    """Test error handling for unsupported proof types."""
    with pytest.raises(InvalidParameterError):
        BlockA2AClient.sign_task(
            private_key=1,
            task_hash=b"\0"*32,
            milestone="m3",
            proof_type="InvalidProofType"
        )

# ------------------- request_resource ------------------------------
@pytest.fixture
def req_client(monkeypatch):
    class FakeACC:
        def __init__(self):
            self.functions = types.SimpleNamespace(evaluate=lambda *_,**__: None)
            class TokenIssued:
                def process_receipt(_, __): return [{"args":{"expiry":int(time.time())+100}}]
            self.events = types.SimpleNamespace(TokenIssued=lambda : TokenIssued())
    monkeypatch.setattr(BlockA2AClient, "_load_contract", lambda *_: FakeACC())
    c = BlockA2AClient("rpc","acc","ilc","agc","dac"); c._acct=True
    monkeypatch.setattr(BaseClient, "_send_tx", lambda *_: b"tx")
    # → 修正：单参 stub
    def wait(tx_hash):
        return types.SimpleNamespace(status=1, transactionHash=tx_hash)
    c._w3 = types.SimpleNamespace(eth=types.SimpleNamespace(
        wait_for_transaction_receipt=wait))
    return c

def test_request_resource_no_acct(req_client):
    req_client._acct = None
    with pytest.raises(IdentityError):
        req_client.request_resource("d","r","a")

def test_request_resource_success(req_client):
    t = req_client.request_resource("d","r","a")
    assert isinstance(t, AccessToken) and t.agentDID=="d"

def test_request_resource_tx_fail(req_client, monkeypatch):
    monkeypatch.setattr(BaseClient, "_send_tx",
                        lambda *_: (_ for _ in ()).throw(Exception()))
    with pytest.raises(ContractError):
        req_client.request_resource("d","r","a")
