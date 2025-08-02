"""Provides cryptographic helper functions for key generation and manipulation.

This module contains self-contained, pure functions for handling key material
across various cryptographic suites. It supports key generation, serialization,
and conversion of public keys to formats suitable for smart contracts.

Supported Suites:
  - Ed25519: Uses raw 32-byte keys and multibase (Base58btc) encoding.
  - BLS12-381/G2: Implements the minimal-pubkey-size standard with 96-byte
    compressed public keys.
  - BN256/G2 (alt_bn128): Uses 64-byte compressed public keys.

Dependencies:
  - cryptography: For Ed25519 operations.
  - py_ecc: For BLS12-381 operations.
  - multibase: For encoding keys with format prefixes.
  - A local bn256 module for BN256/alt_bn128 operations.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
import secrets
from typing import Dict, List, Union, Literal

import multibase
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
# BLS12-381 imports
from py_ecc.bls.ciphersuites import BaseG2Ciphersuite
from py_ecc.bls.point_compression import compress_G2 as compress_g2_bls, decompress_G2 as decompress_g2_bls
from py_ecc.bls.typing import G2Compressed
from py_ecc.optimized_bls12_381 import G2, multiply, normalize

# BN256 (alt_bn128) library import
from src.blocka2a.utils import bn256 as bls_bn256
from src.blocka2a.types import Proof

# --- Constants ---

# Multicodec prefixes for public key types.
_MB_ED_PREFIX: bytes = b"\xed\x01"   # 0xed: Ed25519-pub
_MB_BLS_PREFIX: bytes = b"\xeb\x01"  # 0xeb: BLS12-381-G2-pub
_MB_BN256_PREFIX: bytes = b"\xea\x01" # 0xea: BN256-G2-pub


def _mb58(data: bytes) -> str:
    """Encodes data into a Base58-btc multibase string (prefix 'z')."""
    return multibase.encode("base58btc", data).decode("ascii")

# --- Ed25519 ---

def gen_ed25519() -> Dict[str, str]:
    """Generates an Ed25519 key pair.

    Returns:
        A dictionary containing the hex-encoded private and public keys,
        and a multibase-encoded public key.
    """
    priv = Ed25519PrivateKey.generate()
    sk_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pk_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    return {
        "private_key_hex": sk_bytes.hex(),
        "public_key_hex": pk_bytes.hex(),
        "public_key_multibase": _mb58(_MB_ED_PREFIX + pk_bytes),
    }

# --- BLS12-381 / G2 (minimal-pubkey-size) ---

def _keygen_bls_g2() -> int:
    """Generates a BLS private key using a cryptographically secure seed."""
    # Per IETF draft-bls-signatures, uses a 32-byte IKM for key generation.
    ikm = secrets.token_bytes(32)
    return BaseG2Ciphersuite.KeyGen(ikm)


def gen_bls12_381_g2() -> Dict[str, Union[str, int]]:
    """Generates a BLS12-381 key pair with a G2 public key.

    The public key is a 96-byte compressed point, compliant with the
    "minimal-pubkey-size" standard.

    Returns:
        A dictionary containing the private key (int and hex), the compressed
        public key (hex), and its multibase representation.
    """
    sk = _keygen_bls_g2()
    pt = multiply(G2, sk)
    z1, z2 = compress_g2_bls(pt)
    pk_bytes = z1.to_bytes(48, "big") + z2.to_bytes(48, "big")

    return {
        "private_key_int": sk,
        "private_key_hex": hex(sk),
        "public_key_hex": pk_bytes.hex(),
        "public_key_multibase": _mb58(_MB_BLS_PREFIX + pk_bytes),
    }


def bls12_381_g2_pubkey_to_coords(pk: bytes | str) -> Dict[str, int]:
    """Converts a compressed BLS12-381 G2 public key to affine FQ² coordinates.

    These coordinates are suitable for use in Solidity smart contracts.

    Args:
        pk: The 96-byte compressed public key as a hex string or bytes.

    Returns:
        A dictionary mapping coordinate names (x_r, x_i, y_r, y_i)
        to their integer values.
    """
    if isinstance(pk, str):
        pk = bytes.fromhex(pk)
    assert len(pk) == 96, "BLS12-381 G2 pubkey must be 96 bytes"

    z1 = int.from_bytes(pk[:48], "big")
    z2 = int.from_bytes(pk[48:], "big")

    x, y, z = decompress_g2_bls(G2Compressed((z1, z2)))
    x_aff, y_aff = normalize((x, y, z))
    x_r, x_i = x_aff.coeffs
    y_r, y_i = y_aff.coeffs

    return {"x_r": x_r, "x_i": x_i, "y_r": y_r, "y_i": y_i}

# --- BN256 / G2 (alt_bn128) ---

def gen_bn256_g2() -> Dict[str, Union[str, int]]:
    """Generates a BN256 (alt_bn128) key pair with a G2 public key.

    This uses the local bn256 module for key generation and compression,
    resulting in a 64-byte compressed public key.

    Returns:
        A dictionary containing the private key (int and hex), the 64-byte
        compressed public key (hex), and its multibase representation.
    """
    sk, pk = bls_bn256.generate_keypair()
    pk_bytes = bls_bn256.compress_g2(pk)

    return {
        "private_key_int": sk,
        "private_key_hex": hex(sk),
        "public_key_hex": pk_bytes.hex(),
        "public_key_multibase": _mb58(_MB_BN256_PREFIX + pk_bytes),
    }

def bn256_g2_pubkey_to_coords(pk: Union[bytes, str]) -> Dict[str, int]:
    """Converts a compressed BN256 G2 public key to affine FQ² coordinates.

    The integer coefficients are extracted from the FQ2 elements and are
    suitable for use in smart contracts expecting uint256 values.

    Args:
        pk: The 64-byte compressed public key as a hex string or bytes.

    Returns:
        A dictionary of affine coordinates (x_r, x_i, y_r, y_i)
        as integers.
    """
    if isinstance(pk, str):
        pk = bytes.fromhex(pk)
    assert len(pk) == 64, "BN256 G2 pubkey must be 64 bytes"

    pk_point = bls_bn256.decompress_g2(pk)
    x_aff, y_aff = pk_point

    x_r, x_i = x_aff.coeffs[0].n, x_aff.coeffs[1].n
    y_r, y_i = y_aff.coeffs[0].n, y_aff.coeffs[1].n

    return {"x_r": x_r, "x_i": x_i, "y_r": y_r, "y_i": y_i}


# --- Batch Generation ---

def generate_key_sets(count: int = 1) -> List[Dict]:
    """Generates a batch of key sets for all supported crypto suites.

    Each set includes Ed25519, BLS12-381, and BN256 keys, along with
    affine coordinates for the G2 public keys.

    Args:
        count: The number of independent key sets to generate.

    Returns:
        A list of dictionaries, where each dictionary represents a
        complete key set.
    """
    out: List[Dict] = []
    for i in range(1, count + 1):
        ed = gen_ed25519()
        bls = gen_bls12_381_g2()
        bls_coords = bls12_381_g2_pubkey_to_coords(bls["public_key_hex"])

        bn256 = gen_bn256_g2()
        bn256_coords = bn256_g2_pubkey_to_coords(bn256["public_key_hex"])

        out.append({
            "set": i,
            "ed25519": ed,
            "bls12_381_g2": {**bls, "g2_affine_coords": bls_coords},
            "bn256_g2": {**bn256, "g2_affine_coords": bn256_coords},
        })
    return out

# --- Ed25519 Signing and Verification ---

def sign(
    message: Union[str, bytes],
    private_key: Union[int, bytes, str],
    proof_type: Literal["Ed25519Signature2020"],
    verification_method: str
) -> Proof:
    """Creates an Ed25519Signature2020 proof for a given message.

    The function serializes a payload containing proof metadata and the
    message, then signs the resulting byte string with the provided key.

    Args:
        message: The message to sign, as a string or bytes.
        private_key: The 32-byte Ed25519 private key (seed).
        proof_type: The signature suite type, must be 'Ed25519Signature2020'.
        verification_method: A URI string identifying the public key.

    Returns:
        A Proof object containing the signature and metadata.

    Raises:
        ValueError: If the proof type is unsupported or the private key
            is not a 32-byte seed.
    """
    if proof_type != "Ed25519Signature2020":
        raise ValueError(f"Unsupported proof type: {proof_type!r}")

    msg = message.encode("utf-8") if isinstance(message, str) else message

    if isinstance(private_key, str):
        key_bytes = bytes.fromhex(private_key)
    else:
        key_bytes = private_key

    if not (isinstance(key_bytes, (bytes, bytearray)) and len(key_bytes) == 32):
        raise ValueError("Ed25519 private key must be 32 bytes (seed)")

    created = datetime.now(timezone.utc)
    # The payload to be signed is a canonicalized JSON object.
    payload = {
        "type": proof_type,
        "created": created.isoformat(),
        "verification_method": verification_method,
        "message": msg.decode("utf-8")
    }
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    priv = Ed25519PrivateKey.from_private_bytes(key_bytes)
    sig_hex = priv.sign(serialized).hex()

    return Proof(
        type=proof_type,
        created=created,
        verificationMethod=verification_method,
        proofValue=sig_hex,
    )


def verify_in_json(
    proof: Proof,
    message: Union[str, bytes],
    public_key: Union[bytes, str]
) -> bool:
    """Verifies an Ed25519Signature2020 proof.

    This function reconstructs the exact signed payload from the proof
    metadata and original message, then verifies the signature against it.

    Args:
        proof: The Proof object to verify.
        message: The original message that was signed.
        public_key: The 32-byte Ed25519 public key.

    Returns:
        True if the signature is valid, False otherwise.

    Raises:
        ValueError: If the proof type is unsupported or the public key
            is not 32 bytes.
    """
    if proof.type != "Ed25519Signature2020":
        raise ValueError(f"Unsupported proof type: {proof.type!r}")

    msg_str = message.decode("utf-8") if isinstance(message, (bytes, bytearray)) else message
    key_bytes = bytes.fromhex(public_key) if isinstance(public_key, str) else public_key
    if not (isinstance(key_bytes, (bytes, bytearray)) and len(key_bytes) == 32):
        raise ValueError("Ed25519 public key must be 32 bytes")

    payload = {
        "type": proof.type,
        "created": proof.created.isoformat(),
        "verification_method": proof.verificationMethod,
        "message": msg_str
    }
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig_bytes = bytes.fromhex(proof.proofValue)
    pub = Ed25519PublicKey.from_public_bytes(key_bytes)

    try:
        pub.verify(sig_bytes, serialized)
        return True
    except InvalidSignature:
        return False

def verify(proof: Proof, message: Union[str, bytes], public_key: Union[bytes, str]) -> bool:
    if proof.type != "Ed25519Signature2020":
        raise ValueError(f"Unsupported proof type: {proof.type!r}")

    msg_bytes = message.encode("utf-8") if isinstance(message, str) else message
    key_bytes = bytes.fromhex(public_key) if isinstance(public_key, str) else public_key
    if not (isinstance(key_bytes, (bytes, bytearray)) and len(key_bytes) == 32):
        raise ValueError("Ed25519 public key must be 32 bytes")

    sig_bytes = bytes.fromhex(proof.proofValue)
    pub = Ed25519PublicKey.from_public_bytes(key_bytes)

    try:
        pub.verify(sig_bytes, msg_bytes)  # 直接验证原始message
        return True
    except InvalidSignature:
        return False


def multibase_to_raw_public_key(mb: str) -> bytes:
    """Converts a multibase-encoded public key to its raw bytes.

    This function decodes a multibase string, strips the multicodec prefix
    (e.g., for Ed25519 or BLS), and returns the raw public key.

    Args:
        mb: A Base58btc multibase string encoding a prefixed public key.

    Returns:
        The raw public key bytes (e.g., 32 for Ed25519, 96 for BLS12-381).

    Raises:
        ValueError: If the decoded data does not start with a known prefix.
    """
    data = multibase.decode(mb)
    if data.startswith(_MB_ED_PREFIX):
        return data[len(_MB_ED_PREFIX):]
    if data.startswith(_MB_BLS_PREFIX):
        return data[len(_MB_BLS_PREFIX):]
    if data.startswith(_MB_BN256_PREFIX):
        return data[len(_MB_BN256_PREFIX):]

    raise ValueError(f"Unknown multicodec prefix in multibase data: {data[:2].hex()}")

__all__ = [
    "gen_ed25519",
    "gen_bls12_381_g2",
    "bls12_381_g2_pubkey_to_coords",
    "gen_bn256_g2",
    "bn256_g2_pubkey_to_coords",
    "generate_key_sets",
    "sign",
    "verify",
    "multibase_to_raw_public_key",
]