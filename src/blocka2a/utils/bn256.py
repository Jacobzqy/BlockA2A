"""
utils.bn256 - BLS Signature Scheme over the alt_bn128 curve.

This library provides a comprehensive suite of functions for BLS signatures,
including key generation, signing, verification, and aggregation, all
compatible with older versions of the `py_ecc` library.
"""

from __future__ import annotations
import secrets
from hashlib import sha256
from typing import List, NewType, Tuple

from py_ecc.bn128 import (
    FQ, FQ2, FQ12,
    G1, G2, Z1, Z2,
    b, b2, curve_order,
    add, multiply, pairing, final_exponentiate, is_on_curve,
    field_modulus as p
)

# --- Type Aliases for Clarity ---
SecretKey = NewType("SecretKey", int)
PointG1 = Tuple[FQ, FQ]
PointG2 = Tuple[FQ2, FQ2]
PublicKey = NewType("PublicKey", PointG2)
Signature = NewType("Signature", PointG1)

# --------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------- #
__all__ = [
    "SecretKey", "PublicKey", "Signature", "PointG1", "PointG2",
    "generate_keypair",
    "compress_g2", "decompress_g2",
    "hash_to_g1",
    "sign",
    "verify_single",
    "aggregate_pks",
    "aggregate_sigs",
    "verify_aggregate",
    "verify_fast_aggregate_same_msg"
]


# --- Key Management & Serialization (Corrected) ---

def generate_keypair() -> Tuple[SecretKey, PublicKey]:
    secret_key = secrets.randbelow(curve_order - 1) + 1
    public_key = multiply(G2, secret_key)
    return SecretKey(secret_key), PublicKey(public_key)


def compress_g2(pk: PublicKey) -> bytes:
    if pk is None or pk == Z2:
        return bytes([0xc0]) + bytes(63)
    x_pair = _pair(pk[0])
    raw = x_pair[0].to_bytes(32, "big") + x_pair[1].to_bytes(32, "big")
    first_byte = raw[0]
    first_byte |= 0x80
    if _sgn0(pk[1]):
        first_byte |= 0x40
    return bytes([first_byte]) + raw[1:]


# 文件: utils/bn256/__init__.py (只展示被修改的 decompress_g2 函数，其余不变)

def decompress_g2(buf: bytes) -> PublicKey:
    """Decompresses 64 bytes into a G2 point (public key)."""
    if len(buf) != 64:
        raise ValueError("Input must be 64 bytes.")

    # 步骤 1: 严格、完整地检查是否为无穷远点的规范编码
    if buf == (bytes([0xc0]) + bytes(63)):
        return Z2

    # 步骤 2: 检查压缩标志位。如果执行到这里，说明它不是无穷远点。
    if not (buf[0] & 0x80):
        raise ValueError("Compression bit is not set.")

    # [删除] 不再需要那个错误的 "if (buf[0] & 0xc0) == 0xc0:" 检查

    # 步骤 3: 正常解析有限点
    sign = (buf[0] & 0x40) >> 6

    x_byte_0 = buf[0] & 0x3F  # Mask out the 2 flag bits
    x_bytes = bytes([x_byte_0]) + buf[1:]

    x1 = int.from_bytes(x_bytes[:32], "big")
    x2 = int.from_bytes(x_bytes[32:], "big")
    x = FQ2([x1, x2])

    y_squared = x ** 3 + b2
    y = _sqrt_fq2(y_squared)

    if _sgn0(y) != sign:
        y = -y

    point = (x, y)
    # 最终的保障：解出的点必须在曲线上。任何无效编码（如0xc001...）到这里都会失败。
    if not is_on_curve(point, b2):
        raise ValueError("Decompressed point is not on the curve.")

    return PublicKey(point)


# --- Signing, Verification & Aggregation (Logic unchanged) ---
# ... (此部分无变化) ...
def hash_to_g1(msg: bytes) -> PointG1:
    nonce = 0
    while True:
        nonce_bytes = nonce.to_bytes(4, 'big')
        hash_input = sha256(msg + nonce_bytes).digest()
        x_val = int.from_bytes(hash_input, 'big') % p
        x = FQ(x_val)
        y_squared = x ** 3 + b
        try:
            y = _sqrt_fq(y_squared)
            point = (x, y)
            if is_on_curve(point, b):
                return point
        except ValueError:
            pass
        finally:
            nonce += 1


def sign(msg: bytes, sk: SecretKey) -> Signature:
    h = hash_to_g1(msg)
    return Signature(multiply(h, sk))


def verify_single(pk: PublicKey, sig: Signature, msg: bytes) -> bool:
    h = hash_to_g1(msg)
    lhs = pairing(G2, sig)
    rhs = pairing(pk, h)
    return final_exponentiate(lhs) == final_exponentiate(rhs)


def aggregate_pks(pks: List[PublicKey]) -> PublicKey:
    if not pks: return Z2
    return PublicKey(add(pks[0], aggregate_pks(pks[1:]))) if len(pks) > 1 else pks[0]


def aggregate_sigs(sigs: List[Signature]) -> Signature:
    if not sigs: return Z1
    return Signature(add(sigs[0], aggregate_sigs(sigs[1:]))) if len(sigs) > 1 else sigs[0]


def verify_aggregate(pks: List[PublicKey], sig_agg: Signature, msgs: List[bytes]) -> bool:
    if len(pks) != len(msgs):
        raise ValueError("Number of public keys and messages must be equal.")
    lhs = pairing(G2, sig_agg)
    rhs = FQ12.one()
    for pk, msg in zip(pks, msgs):
        h = hash_to_g1(msg)
        rhs *= pairing(pk, h)
    return final_exponentiate(lhs) == final_exponentiate(rhs)


def verify_fast_aggregate_same_msg(pks: List[PublicKey], sig_agg: Signature, msg: bytes) -> bool:
    pk_agg = aggregate_pks(pks)
    h = hash_to_g1(msg)
    lhs = pairing(G2, sig_agg)
    rhs = pairing(pk_agg, h)
    return final_exponentiate(lhs) == final_exponentiate(rhs)


# --- Internal Helpers (Logic unchanged) ---
# ... (此部分无变化) ...
def _pair(z: FQ2) -> Tuple[int, int]:
    a, b = z.coeffs
    return int(getattr(a, "n", a)), int(getattr(b, "n", b))


def _sgn0(z: FQ2) -> int:
    a, b = _pair(z)
    return (b & 1) if b != 0 else (a & 1)


def _inv_fq(n_fq: FQ) -> FQ:
    n = n_fq.n
    if n == 0: raise ZeroDivisionError("Cannot compute inverse of zero.")
    return FQ(pow(n, p - 2, p))


def _sqrt_fq(n_fq: FQ) -> FQ:
    n = n_fq.n
    if n == 0: return FQ.zero()
    if pow(n, (p - 1) // 2, p) != 1: raise ValueError("Not a quadratic residue")
    Q, S = p - 1, 0
    while Q % 2 == 0: S += 1; Q //= 2
    z = next(FQ(i) for i in range(2, p) if pow(i, (p - 1) // 2, p) != 1)
    M, c, t, R = S, z ** Q, n_fq ** Q, n_fq ** ((Q + 1) // 2)
    while t != FQ.one():
        if t == FQ.zero(): return FQ.zero()
        i, temp_t = 0, t
        while temp_t != FQ.one(): temp_t = temp_t * temp_t; i += 1
        b = c ** (2 ** (M - i - 1))
        M, c, t, R = i, b * b, t * c, R * b
    return R


def _sqrt_fq2(v: FQ2) -> FQ2:
    if v == FQ2.zero(): return FQ2.zero()
    a, b_ = v.coeffs
    two_inv = FQ((p + 1) // 2)
    if b_ == FQ.zero():
        try:
            return FQ2([_sqrt_fq(a), FQ.zero()])
        except ValueError:
            return FQ2([FQ.zero(), _sqrt_fq(-a)])
    delta = a * a + b_ * b_
    s = _sqrt_fq(delta)
    try:
        x = _sqrt_fq((a + s) * two_inv)
        y = b_ * _inv_fq(x * 2)
        return FQ2([x, y])
    except ValueError:
        x = _sqrt_fq((a - s) * two_inv)
        y = b_ * _inv_fq(x * 2)
        return FQ2([x, y])