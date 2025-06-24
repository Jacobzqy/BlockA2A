# tests/utils/test_ipfs.py

import json
import pytest
import ipfshttpclient
from ipfshttpclient.exceptions import Error as IPFSError

from src.blocka2a.utils.ipfs import IPFSClient


def test_init_connects_to_gateway(monkeypatch):
    gateway = "/ip4/127.0.0.1/tcp/5001/http"
    called = {}

    def fake_connect(gw):
        called['gateway'] = gw
        class DummyClient:
            pass
        return DummyClient()

    monkeypatch.setattr(ipfshttpclient, "connect", fake_connect)
    client = IPFSClient(gateway)
    assert called['gateway'] == gateway
    assert hasattr(client, "_client")


def test_add_bytes_success_and_error(monkeypatch):
    # 成功场景
    class FakeSuccess:
        def __init__(self, gw): pass
        def add_bytes(self, data):
            assert data == b"hello"
            return "CID_BYTES"

    monkeypatch.setattr(ipfshttpclient, "connect", lambda gw: FakeSuccess(gw))
    client = IPFSClient("/ip4/127.0.0.1/tcp/5001/http")
    assert client.add_bytes(b"hello") == "CID_BYTES"

    # 失败场景：IPFSError 应向上抛
    class FakeError:
        def __init__(self, gw): pass
        def add_bytes(self, data):
            raise IPFSError("boom")

    monkeypatch.setattr(ipfshttpclient, "connect", lambda gw: FakeError(gw))
    client_err = IPFSClient("/ip4/127.0.0.1/tcp/5001/http")
    with pytest.raises(IPFSError):
        client_err.add_bytes(b"data")


def test_add_json_native_and_fallback(monkeypatch):
    # 原生 add_json 存在
    class FakeNative:
        def __init__(self, gw): pass
        def add_json(self, obj):
            assert obj == {"x": 1}
            return "CID_JSON"

    monkeypatch.setattr(ipfshttpclient, "connect", lambda gw: FakeNative(gw))
    client = IPFSClient("/ip4/127.0.0.1/tcp/5001/http")
    assert client.add_json({"x": 1}) == "CID_JSON"

    # 原生 add_json 不存在，退回到 add_bytes
    recorded = {}
    class FakeFallback:
        def __init__(self, gw): pass
        # 注意：不定义 add_json，就会触发 AttributeError
        def add_bytes(self, data):
            recorded['data'] = data
            return "CID_FALLBACK"

    monkeypatch.setattr(ipfshttpclient, "connect", lambda gw: FakeFallback(gw))
    client_fb = IPFSClient("/ip4/127.0.0.1/tcp/5001/http")
    cid = client_fb.add_json({"x": 1, "y": 2})
    assert cid == "CID_FALLBACK"
    expected = json.dumps({"x": 1, "y": 2}, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert recorded['data'] == expected


def test_add_file_various_formats_and_error(monkeypatch, tmp_path):
    # 列表格式返回
    class FakeList:
        def __init__(self, gw): pass
        def add_file(self, path):
            return [{"Hash": "h1"}, {"hash": "h2"}]

    monkeypatch.setattr(ipfshttpclient, "connect", lambda gw: FakeList(gw))
    client = IPFSClient("/ip4/127.0.0.1/tcp/5001/http")
    assert client.add_file(tmp_path / "file.txt") == "h2"

    # 单 dict 返回（小写 hash）
    class FakeDictLower:
        def __init__(self, gw): pass
        def add_file(self, path):
            return {"hash": "h3"}

    monkeypatch.setattr(ipfshttpclient, "connect", lambda gw: FakeDictLower(gw))
    client2 = IPFSClient("/ip4/127.0.0.1/tcp/5001/http")
    assert client2.add_file("some/path") == "h3"

    # 单 dict 返回（大写 Hash）
    class FakeDictUpper:
        def __init__(self, gw): pass
        def add_file(self, path):
            return {"Hash": "h4"}

    monkeypatch.setattr(ipfshttpclient, "connect", lambda gw: FakeDictUpper(gw))
    client3 = IPFSClient("/ip4/127.0.0.1/tcp/5001/http")
    assert client3.add_file("p") == "h4"

    # 返回不含 hash 字段，应抛 RuntimeError
    class FakeBad:
        def __init__(self, gw): pass
        def add_file(self, path):
            return {"foo": "bar"}

    monkeypatch.setattr(ipfshttpclient, "connect", lambda gw: FakeBad(gw))
    client_bad = IPFSClient("/ip4/127.0.0.1/tcp/5001/http")
    with pytest.raises(RuntimeError):
        client_bad.add_file("p")


def test_get_and_get_json(monkeypatch):
    # get 返回原始 bytes
    class FakeCat:
        def __init__(self, gw): pass
        def cat(self, cid):
            assert cid == "CID123"
            return b'{"foo": "bar"}'

    monkeypatch.setattr(ipfshttpclient, "connect", lambda gw: FakeCat(gw))
    client = IPFSClient("/ip4/127.0.0.1/tcp/5001/http")
    raw = client.get("CID123")
    assert raw == b'{"foo": "bar"}'

    # get_json 正常
    obj = client.get_json("CID123")
    assert obj == {"foo": "bar"}

    # get_json 异常
    class FakeCatBad:
        def __init__(self, gw): pass
        def cat(self, cid):
            return b"not a json"

    monkeypatch.setattr(ipfshttpclient, "connect", lambda gw: FakeCatBad(gw))
    client_bad = IPFSClient("/ip4/127.0.0.1/tcp/5001/http")
    with pytest.raises(json.JSONDecodeError):
        client_bad.get_json("CID123")


def test_close_no_error_and_with_error(monkeypatch):
    # 正常关闭
    class FakeClose:
        def __init__(self, gw): pass
        def close(self):
            self.closed = True

    fake = FakeClose("gw")
    monkeypatch.setattr(ipfshttpclient, "connect", lambda gw: fake)
    client = IPFSClient("/ip4/127.0.0.1/tcp/5001/http")
    client.close()
    assert getattr(fake, "closed", False)

    # 关闭时报错也不抛出
    class FakeCloseError:
        def __init__(self, gw): pass
        def close(self):
            raise IPFSError("oops")

    fake_err = FakeCloseError("gw")
    monkeypatch.setattr(ipfshttpclient, "connect", lambda gw: fake_err)
    client_err = IPFSClient("/ip4/127.0.0.1/tcp/5001/http")
    # 不应抛异常
    client_err.close()
