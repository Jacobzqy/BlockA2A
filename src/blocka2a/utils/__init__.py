"""
BlockA2A Utility Sub-package
============================

Common helper modules shipped with the BlockA2A SDK.

Modules
-------
ipfs
    ``IPFSClient`` – thin wrapper around a local/remote IPFS daemon.
crypto
    Ed25519 / BLS12-381 key helpers (see ``blocka2a.utils.crypto``).
bn256
    BLS signature helpers over the BN254/alt_bn128 curve.

"""
from .ipfs import IPFSClient
from .crypto import (
    gen_ed25519,
    gen_bls12_381_g2,
    bls12_381_g2_pubkey_to_coords,
    generate_key_sets,
)
# 新增：从 bn256 模块导入相关功能
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
)


__all__ = [
    # ipfs
    "IPFSClient",
    # crypto helpers
    "gen_ed25519",
    "gen_bls12_381_g2",
    "bls12_381_g2_pubkey_to_coords",
    "generate_key_sets",

    # 新增：导出 bn256 的类型和函数
    # Types
    "SecretKey",
    "PublicKey",
    "Signature",
    # Functions
    "generate_keypair",
    "compress_g2",
    "decompress_g2",
    "hash_to_g1",
    "sign",
    "verify_single",
    "aggregate_pks",
    "aggregate_sigs",
    "verify_aggregate",
    "verify_fast_aggregate_same_msg",
]