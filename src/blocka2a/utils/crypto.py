"""
blocka2a.utils.crypto
~~~~~~~~~~~~~~~~~~~~~~~~~~

Self-contained helper functions for generating and manipulating key material
for various cryptographic suites. All routines are pure and side-effect free.

Supported Suites:
* Ed25519: Raw 32-byte keys + multibase58 public key.
* BLS12-381/G2: 96-byte compressed public key (minimal-pubkey-size).
* BN256/G2 (alt_bn128): 64-byte compressed public key.

Also provides utilities to convert compressed G2 public keys into their
affine FQ² coordinates (x_r, x_i, y_r, y_i), ready for Solidity.

Dependencies
------------
`cryptography`, `py_ecc`, `multibase`, and the local `bn256` module.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
import secrets
from typing import Dict, List, Tuple, Optional, Union, Literal

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
from . import bn256 as bls_bn256

from src.blocka2a.types import Proof

# --------------------------------------------------------------------------- #
# Constants                                                                   #
# --------------------------------------------------------------------------- #

_MB_ED_PREFIX: bytes = b"\xed\x01"   # multicodec 0xED = Ed25519-pub
_MB_BLS_PREFIX: bytes = b"\xeb\x01"  # multicodec 0xEB = BLS12-381-G2-pub
_MB_BN256_PREFIX: bytes = b"\xea\x01" # multicodec 0xEA (placeholder) for bn256-g2-pub


def _mb58(data: bytes) -> str:
    """Return a Base58-btc multibase string (`z…`)."""
    return multibase.encode("base58btc", data).decode("ascii")

# --------------------------------------------------------------------------- #
# Ed25519                                                                     #
# --------------------------------------------------------------------------- #

def gen_ed25519() -> Dict[str, str]:
    """Generate a single Ed25519 key pair."""
    priv = Ed25519PrivateKey.generate()
    sk_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pk_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    return {
        "private_key_hex": sk_bytes.hex(),
        "public_key_hex": pk_bytes.hex(),
        "public_key_multibase": _mb58(_MB_ED_PREFIX + pk_bytes),
    }

# --------------------------------------------------------------------------- #
# BLS12-381 / G2 (minimal-pubkey)                                             #
# --------------------------------------------------------------------------- #

def _keygen_bls_g2() -> int:
    """Generate a BLS private key via HKDF (IETF draft-bls-signatures)."""
    ikm = secrets.token_bytes(32)
    return BaseG2Ciphersuite.KeyGen(ikm)

def gen_bls12_381_g2() -> Dict[str, str | int]:
    """Generate a single BLS12-381/G2 key pair."""
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
    """Convert a compressed BLS12-381 G2 public key to affine FQ² coordinates."""
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

# --------------------------------------------------------------------------- #
# BN256 / G2 (alt_bn128)                                                      #
# --------------------------------------------------------------------------- #

def gen_bn256_g2() -> Dict[str, str | int]:
    """
    Generate a single BN256/G2 (alt_bn128) key pair.

    Returns
    -------
    Dict[str, str | int]
        * ``private_key_int`` – private scalar as Python ``int``
        * ``private_key_hex`` – same value, hex-encoded with ``0x`` prefix
        * ``public_key_hex`` – 64-byte compressed G2 pk, lower-hex
        * ``public_key_multibase`` – Base58-btc string with a G2 multicodec
    """
    sk, pk = bls_bn256.generate_keypair()
    pk_bytes = bls_bn256.compress_g2(pk)

    return {
        "private_key_int": sk,
        "private_key_hex": hex(sk),
        "public_key_hex": pk_bytes.hex(),
        "public_key_multibase": _mb58(_MB_BN256_PREFIX + pk_bytes),
    }


def bn256_g2_pubkey_to_coords(pk: bytes | str) -> Dict[str, int]:
    """
    Convert a compressed BN256/G2 public key to affine FQ² coordinates.

    Parameters
    ----------
    pk : bytes | str
        64-byte compressed key (bytes) **or** its lower-hex string.

    Returns
    -------
    Dict[str, int]
        Mapping ``{x_r, x_i, y_r, y_i}``; each value fits in ``uint256``.
    """
    if isinstance(pk, str):
        pk = bytes.fromhex(pk)
    assert len(pk) == 64, "BN256 G2 pubkey must be 64 bytes"

    # Decompress the point to get its affine coordinates
    pk_point = bls_bn256.decompress_g2(pk)
    x_aff, y_aff = pk_point

    # Extract integer coefficients from FQ2 elements
    x_r, x_i = x_aff.coeffs[0].n, x_aff.coeffs[1].n
    y_r, y_i = y_aff.coeffs[0].n, y_aff.coeffs[1].n

    return {"x_r": x_r, "x_i": x_i, "y_r": y_r, "y_i": y_i}


# --------------------------------------------------------------------------- #
# Batch helper                                                                #
# --------------------------------------------------------------------------- #

def generate_key_sets(count: int = 1) -> List[Dict]:
    """
    Generate *count* independent key sets (Ed25519, BLS12-381, and BN256).
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

# --------------------------------------------------------------------------- #
# Ed25519 Signing / Verification (as provided)                                #
# --------------------------------------------------------------------------- #

def sign(
    message: Union[str, bytes],
    private_key: Union[int, bytes, str],
    proof_type: Literal["Ed25519Signature2020"],
    verification_method: str
) -> Proof:
    if proof_type != "Ed25519Signature2020":
        raise ValueError(f"Unsupported proof type: {proof_type!r}")

    msg = message.encode("utf-8") if isinstance(message, str) else message

    if isinstance(private_key, str):
        key_bytes = bytes.fromhex(private_key)
    else:
        key_bytes = private_key

    # [修正] Ed25519 的原始私钥（种子）应该是 32 字节
    if not (isinstance(key_bytes, (bytes, bytearray)) and len(key_bytes) == 32):
        raise ValueError("Ed25519 private key must be 32 bytes (seed)")

    created = datetime.now(timezone.utc)
    payload = {
        "type": proof_type,
        "created": created.isoformat(),
        "verification_method": verification_method,
        "message": msg.decode("utf-8")
    }
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    # from_private_bytes 正确地从 32 字节种子加载私钥
    priv = Ed25519PrivateKey.from_private_bytes(key_bytes)
    sig_hex = priv.sign(serialized).hex()

    return Proof(
        type=proof_type,
        created=created,
        verificationMethod=verification_method,
        proofValue=sig_hex,
    )

def verify(
    proof: Proof,
    message: Union[str, bytes],
    public_key: Union[bytes, str]
) -> bool:
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
    except InvalidSignature:
        return False

    return True

def multibase_to_raw_public_key(
    mb: str
) -> bytes:
    """Convert a Base58btc multibase-encoded public key into raw key bytes.

    This will:
      1. Decode the multibase string (e.g. "z…") into bytes.
      2. Strip off the multicodec prefix (_MB_ED_PREFIX / _MB_BLS_PREFIX / _MB_BN256_PREFIX).
      3. Return the remaining raw public-key bytes.

    Args:
        mb: A Base58btc multibase string that encodes
            multicodec-prefix + public key.

    Returns:
        The raw public key bytes (32 bytes for Ed25519,
        96 bytes for BLS12-381/G2, 64 bytes for BN256/G2).

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

    # 如果都不匹配，则抛错
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