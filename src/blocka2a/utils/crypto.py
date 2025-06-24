"""
blocka2a.utils.crypto
~~~~~~~~~~~~~~~~~~~~~~~~~~

Self-contained helper functions for generating and manipulating
Ed25519 and BLS12-381/G2 key material.  All routines are pure and
side-effect free, so that they can be imported from any layer of
the BlockA2A code-base or unit-tested in isolation.

* Ed25519 keys are returned in raw 32-byte form (+ multibase58 pk).
* BLS keys follow the “minimal-pubkey-size” variant  
  (PK ∈ G2 — 96 bytes compressed, SK is an integer).
* A small utility converts a compressed G2 public key into its
  affine FQ² coordinates (x_r, x_i, y_r, y_i) — ready for Solidity
  `uint256[4]`.

Dependencies
------------
`cryptography`, `py_ecc>=7.0.0`, and `multibase`
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
import random
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
from py_ecc.bls.ciphersuites import BaseG2Ciphersuite
from py_ecc.bls.point_compression import compress_G2, decompress_G2
from py_ecc.bls.typing import G2Compressed
from py_ecc.optimized_bls12_381 import G2, multiply, normalize
from py_ecc.optimized_bn128 import (
    G2 as G2_BN128,  # 重命名以避免与可能存在的G2_BLS12_381冲突
    curve_order as CURVE_ORDER_BN128,
    multiply as multiply_bn128,
    normalize as normalize_bn128,
    b2, field_modulus
)

from py_ecc.fields import optimized_bn128_FQ2 as FQ2, optimized_bn128_FQ as FQ

from src.blocka2a.types import Proof

# --------------------------------------------------------------------------- #
# Constants                                                                   #
# --------------------------------------------------------------------------- #

_MB_ED_PREFIX: bytes = b"\xed\x01"   # multicodec 0xED = Ed25519-pub
_MB_BLS_PREFIX: bytes = b"\xeb\x01"  # multicodec 0xEB = BLS12-381-G2-pub


def _mb58(data: bytes) -> str:
    """Return a Base58-btc multibase string (`z…`)."""
    return multibase.encode("base58btc", data).decode("ascii")

# --------------------------------------------------------------------------- #
# Ed25519                                                                     #
# --------------------------------------------------------------------------- #

def gen_ed25519() -> Dict[str, str]:
    """Generate a single Ed25519 key pair.

    Returns
    -------
    Dict[str, str]
        * ``private_key_hex`` – 64-char lower-hex private key
        * ``public_key_hex``  – 64-char lower-hex public key
        * ``public_key_multibase`` – Base58-btc string starting with ``z``.
    """
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
    """Generate a single BLS12-381/G2 key pair.

    Returns
    -------
    Dict[str, str | int]
        * ``private_key_int`` – private scalar as Python ``int``
        * ``private_key_hex`` – same value, hex-encoded with ``0x`` prefix
        * ``public_key_hex`` – 96-byte compressed G2 pk, lower-hex
        * ``public_key_multibase`` – Base58-btc string with G2 multicodec
    """
    sk = _keygen_bls_g2()
    pt = multiply(G2, sk)                     # projective G2 point
    z1, z2 = compress_G2(pt)                  # two 48-byte limbs
    pk_bytes = z1.to_bytes(48, "big") + z2.to_bytes(48, "big")

    return {
        "private_key_int": sk,
        "private_key_hex": hex(sk),
        "public_key_hex": pk_bytes.hex(),
        "public_key_multibase": _mb58(_MB_BLS_PREFIX + pk_bytes),
    }


def bls_g2_pubkey_to_coords(pk: bytes | str) -> Dict[str, int]:
    """Convert a compressed G2 public key to affine FQ² coordinates.

    Parameters
    ----------
    pk : bytes | str
        96-byte compressed key (bytes) **or** its lower-hex string.

    Returns
    -------
    Dict[str, int]
        Mapping ``{x_r, x_i, y_r, y_i}``; each value fits in ``uint256``.
    """
    if isinstance(pk, str):
        pk = bytes.fromhex(pk)
    assert len(pk) == 96, "G2 pubkey must be 96 bytes"

    z1 = int.from_bytes(pk[:48], "big")
    z2 = int.from_bytes(pk[48:], "big")

    x, y, z = decompress_G2(G2Compressed((z1, z2)))
    x_aff, y_aff = normalize((x, y, z))
    x_r, x_i = x_aff.coeffs
    y_r, y_i = y_aff.coeffs

    return {"x_r": x_r, "x_i": x_i, "y_r": y_r, "y_i": y_i}

# --------------------------------------------------------------------------- #
# Batch helper                                                                #
# --------------------------------------------------------------------------- #

def generate_key_sets(count: int = 1) -> List[Dict]:
    """Generate *count* independent key sets (Ed25519 + BLS).

    Parameters
    ----------
    count : int, optional
        Number of sets to generate, by default ``1``.

    Returns
    -------
    List[Dict]
        Each entry has the shape::

            {
              "set": 1,
              "ed25519": {...},
              "bls12_381_g2": {
                   ...,
                   "g2_affine_coords": {...}
              }
            }
    """
    out: List[Dict] = []
    for i in range(1, count + 1):
        ed = gen_ed25519()
        bls = gen_bls12_381_g2()
        coords = bls_g2_pubkey_to_coords(bls["public_key_hex"])

        out.append({
            "set": i,
            "ed25519": ed,
            "bls12_381_g2": {**bls, "g2_affine_coords": coords},
        })
    return out

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

    if not (isinstance(key_bytes, (bytes, bytearray)) and len(key_bytes) == 32):
        raise ValueError("Ed25519 private key must be 32 bytes")

    created = datetime.now(timezone.utc)
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

__all__ = [
    "gen_ed25519",
    "gen_bls12_381_g2",
    "bls_g2_pubkey_to_coords",
    "generate_key_sets",
    "sign",
    "verify",
]