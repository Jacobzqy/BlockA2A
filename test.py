#!/usr/bin/env python3
# test.py
"""
Test suite for blocka2a.utils.crypto.sign and verify functions.
"""
import json
from datetime import timedelta, timezone
from src.blocka2a.utils.crypto import gen_ed25519, sign, verify
from src.blocka2a.types import Proof

def print_proof(proof: Proof, *, exclude_none: bool = False) -> None:
    """Helper: pretty-print a Proof model via model_dump + json.dumps,
    and serialize datetime to ISO string."""
    # 先 dump 成 dict
    data = proof.model_dump(exclude_none=exclude_none)
    # 把 created 字段转成字符串
    if "created" in data and isinstance(data["created"], (str,)):
        # 如果已经是 str，就不用处理
        pass
    else:
        data["created"] = data["created"].isoformat()
    print(json.dumps(data, indent=2, ensure_ascii=False))


def test_sign_and_verify():
    print("\n=== test_sign_and_verify ===")
    ed = gen_ed25519()
    sk = ed["private_key_hex"]
    pk = ed["public_key_hex"]
    message = "Hello BlockA2A"

    proof: Proof = sign(
        message=message,
        private_key=sk,
        proof_type="Ed25519Signature2020",
        verification_method="did:example:alice#key-1",
    )

    print("Generated Proof:")
    print_proof(proof, exclude_none=True)

    ok = verify(proof=proof, message=message, public_key=pk)
    print("Verification result:", ok)
    assert ok, "Valid proof should verify"
    print("✅ test_sign_and_verify passed")


def test_verify_with_wrong_message():
    print("\n=== test_verify_with_wrong_message ===")
    ed = gen_ed25519()
    sk = ed["private_key_hex"]
    pk = ed["public_key_hex"]
    message = "Original Message"
    proof = sign(
        message=message,
        private_key=sk,
        proof_type="Ed25519Signature2020",
        verification_method="did:example:alice#key-1",
    )

    print("Proof for original message:")
    print_proof(proof)

    ok = verify(proof=proof, message=message + "!", public_key=pk)
    print("Verification with wrong message result:", ok)
    assert not ok, "Verification with wrong message should fail"
    print("✅ test_verify_with_wrong_message passed")


def test_verify_with_wrong_public_key():
    print("\n=== test_verify_with_wrong_public_key ===")
    ed1 = gen_ed25519()
    proof = sign(
        message="Msg",
        private_key=ed1["private_key_hex"],
        proof_type="Ed25519Signature2020",
        verification_method="did:example:alice#key-1",
    )

    print("Proof signed with first key:")
    print_proof(proof)

    ed2 = gen_ed25519()
    pk2 = ed2["public_key_hex"]
    ok = verify(proof=proof, message="Msg", public_key=pk2)
    print("Verification with wrong public key result:", ok)
    assert not ok, "Verification with wrong public key should fail"
    print("✅ test_verify_with_wrong_public_key passed")


def test_verify_with_tampered_signature():
    print("\n=== test_verify_with_tampered_signature ===")
    ed = gen_ed25519()
    sk = ed["private_key_hex"]
    pk = ed["public_key_hex"]
    proof = sign(
        message="BlockA2A",
        private_key=sk,
        proof_type="Ed25519Signature2020",
        verification_method="did:example:alice#key-1",
    )

    print("Original Proof:")
    print_proof(proof)

    # 人为篡改 proofValue
    tampered = proof.copy()
    last_char = tampered.proofValue[-1]
    tampered.proofValue = (
        tampered.proofValue[:-1]
        + ("0" if last_char != "0" else "1")
    )
    print("Tampered Proof:")
    print_proof(tampered)

    ok = verify(proof=tampered, message="BlockA2A", public_key=pk)
    print("Verification with tampered signature result:", ok)
    assert not ok, "Verification with tampered signature should fail"
    print("✅ test_verify_with_tampered_signature passed")


def test_verify_with_expired_timestamp():
    print("\n=== test_verify_with_expired_timestamp ===")
    ed = gen_ed25519()
    sk = ed["private_key_hex"]
    pk = ed["public_key_hex"]
    proof = sign(
        message="ReplayTest",
        private_key=sk,
        proof_type="Ed25519Signature2020",
        verification_method="did:example:alice#key-1",
    )

    print("Current Proof:")
    print_proof(proof)

    # 模拟 created 过期：回退 10 分钟
    expired = proof.copy()
    expired.created = proof.created - timedelta(minutes=10)
    print("Expired Proof (adjusted created):")
    print_proof(expired)

    ok = verify(
        proof=expired,
        message="ReplayTest",
        public_key=pk,
    )
    print("Verification with expired timestamp result:", ok)
    assert not ok, "Verification with expired timestamp should fail"
    print("✅ test_verify_with_expired_timestamp passed")


if __name__ == "__main__":
    test_sign_and_verify()
    test_verify_with_wrong_message()
    test_verify_with_wrong_public_key()
    test_verify_with_tampered_signature()
    test_verify_with_expired_timestamp()
    print("\n🎉 All tests passed!")