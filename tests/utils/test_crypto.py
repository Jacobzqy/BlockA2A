# tests/test_crypto.py

import pytest
from src.blocka2a.utils.crypto import gen_ed25519, sign, verify
from src.blocka2a.types import Proof


@pytest.fixture
def ed_keys():
    """生成一对 Ed25519 密钥对（hex 格式）。"""
    keys = gen_ed25519()
    return {
        "sk": keys["private_key_hex"],
        "pk": keys["public_key_hex"],
    }


def test_sign_and_verify(ed_keys):
    """签名并验证应通过。"""
    message = "Hello BlockA2A"
    proof: Proof = sign(
        message=message,
        private_key=ed_keys["sk"],
        proof_type="Ed25519Signature2020",
        verification_method="did:example:alice#key-1",
    )
    assert verify(
        proof=proof,
        message=message,
        public_key=ed_keys["pk"],
    ), "Valid proof should verify"


def test_verify_with_wrong_message(ed_keys):
    """用错误消息验签应失败。"""
    proof = sign(
        message="Original Message",
        private_key=ed_keys["sk"],
        proof_type="Ed25519Signature2020",
        verification_method="did:example:alice#key-1",
    )
    assert not verify(
        proof=proof,
        message="Original Message!",
        public_key=ed_keys["pk"],
    ), "Verification with wrong message should fail"


def test_verify_with_wrong_public_key(ed_keys):
    """用错误公钥验签应失败。"""
    proof = sign(
        message="Msg",
        private_key=ed_keys["sk"],
        proof_type="Ed25519Signature2020",
        verification_method="did:example:alice#key-1",
    )
    other = gen_ed25519()
    assert not verify(
        proof=proof,
        message="Msg",
        public_key=other["public_key_hex"],
    ), "Verification with wrong public key should fail"


def test_verify_with_tampered_signature(ed_keys):
    """篡改签名后验签应失败。"""
    proof = sign(
        message="BlockA2A",
        private_key=ed_keys["sk"],
        proof_type="Ed25519Signature2020",
        verification_method="did:example:alice#key-1",
    )
    # 用 model_copy 更新 proofValue 最后一位，模拟篡改
    original = proof.proofValue
    last = original[-1]
    flipped = ("0" if last != "0" else "1")
    tampered = proof.model_copy(update={"proofValue": original[:-1] + flipped})

    assert not verify(
        proof=tampered,
        message="BlockA2A",
        public_key=ed_keys["pk"],
    ), "Verification with tampered signature should fail"
