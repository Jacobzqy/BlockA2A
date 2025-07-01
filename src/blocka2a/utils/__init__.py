"""Initializes the BlockA2A utilities sub-package.

This package bundles common helper modules for the BlockA2A SDK, covering
cryptographic operations and distributed storage interaction. This `__init__.py`
file exposes the most important classes and functions from the sub-modules,
allowing for convenient, direct access.

Available Utilities:
  - ipfs: Provides the IPFSClient class for simplified interaction with a
    local or remote IPFS daemon.
  - crypto: Contains high-level helper functions for generating key pairs
    for various cryptographic suites like Ed25519 and BLS12-381.
  - bn256: Offers a complete implementation of the BLS signature scheme over
    the BN256 (alt_bn128) curve, including types and functions for key
    generation, signing, verification, and aggregation.
"""
from .ipfs import IPFSClient
from .crypto import (
    gen_ed25519,
    gen_bls12_381_g2,
    bls12_381_g2_pubkey_to_coords,
    generate_key_sets,
)
# Expose the full BN256 BLS signature suite.
from .bn256 import (
    SecretKey,
    PublicKey,
    Signature,
    generate_keypair,
    compress_g2,
    decompress_g2,
    hash_to_g1,
    sign,
    verify_single,
    aggregate_pks,
    aggregate_sigs,
    verify_aggregate,
    verify_fast_aggregate_same_msg,
    deserialize_g1,
)


__all__ = [
    # from .ipfs
    "IPFSClient",
    # from .crypto
    "gen_ed25519",
    "gen_bls12_381_g2",
    "bls12_381_g2_pubkey_to_coords",
    "generate_key_sets",

    # from .bn256
    "SecretKey",
    "PublicKey",
    "Signature",
    "generate_keypair",
    "compress_g2",
    "decompress_g2",
    "deserialize_g1",
    "hash_to_g1",
    "sign",
    "verify_single",
    "aggregate_pks",
    "aggregate_sigs",
    "verify_aggregate",
    "verify_fast_aggregate_same_msg",
]