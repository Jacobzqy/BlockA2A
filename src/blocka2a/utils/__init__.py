"""
BlockA2A Utility Sub-package
============================

Common helper modules shipped with the BlockA2A SDK.

Modules
-------
ipfs
    ``IPFSClient`` – thin wrapper around a local/remote IPFS daemon.
crypto
    Ed25519 / BLS-12-381 key helpers (see ``blocka2a.utils.crypto``).
"""
from .ipfs import IPFSClient
from .crypto import (
    gen_ed25519,
    gen_bls12_381_g2,
    bls12_381_g2_pubkey_to_coords,
    generate_key_sets,
)


__all__ = [
    # ipfs
    "IPFSClient",
    # crypto helpers
    "gen_ed25519",
    "gen_bls12_381_g2",
    "bls12_381_g2_pubkey_to_coords",
    "generate_key_sets",
]