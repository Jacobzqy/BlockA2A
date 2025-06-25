from __future__ import annotations
import secrets
from hashlib import sha256  # (sha256 no longer used for hashing to curve)
from typing import List, NewType, Tuple
from py_ecc.bn128 import (
    FQ, FQ2, FQ12,
    G1, G2, Z1, Z2,
    b, b2, curve_order,
    add, multiply, pairing, final_exponentiate, is_on_curve,
    field_modulus as p
)
from Crypto.Hash import keccak  # using pycryptodome for keccak256

# --- Type Aliases ---
SecretKey = NewType("SecretKey", int)
PointG1 = Tuple[FQ, FQ]
PointG2 = Tuple[FQ2, FQ2]
PublicKey = NewType("PublicKey", PointG2)
Signature = NewType("Signature", PointG1)

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

# --- Key Generation ---
def generate_keypair() -> Tuple[SecretKey, PublicKey]:
    secret_key = secrets.randbelow(curve_order - 1) + 1
    public_key = multiply(G2, secret_key)
    return SecretKey(secret_key), PublicKey(public_key)

# --- G2 Compression/Decompression (unchanged except bugfix in decompress_g2) ---
def compress_g2(pk: PublicKey) -> bytes:
    if pk is None or pk == Z2:
        return bytes([0xc0]) + bytes(63)
    x_pair = _pair(pk[0])
    raw = x_pair[0].to_bytes(32, "big") + x_pair[1].to_bytes(32, "big")
    first_byte = raw[0] | 0x80
    if _sgn0(pk[1]):
        first_byte |= 0x40
    return bytes([first_byte]) + raw[1:]

def decompress_g2(buf: bytes) -> PublicKey:
    if len(buf) != 64:
        raise ValueError("Input must be 64 bytes.")
    # Step 1: check infinity encoding
    if buf == (bytes([0xc0]) + bytes(63)):
        return Z2
    # Step 2: compression flag must be set
    if not (buf[0] & 0x80):
        raise ValueError("Compression bit is not set.")
    # (Removed the old incorrect check for 0xc0 prefix with other bits)
    sign = (buf[0] & 0x40) >> 6
    x_byte_0 = buf[0] & 0x3F  # mask out flag bits
    x_bytes = bytes([x_byte_0]) + buf[1:]
    x1 = int.from_bytes(x_bytes[:32], "big")
    x2 = int.from_bytes(x_bytes[32:], "big")
    x = FQ2([x1, x2])
    y_squared = x ** 3 + b2
    y = _sqrt_fq2(y_squared)
    if _sgn0(y) != sign:
        y = -y
    point = (x, y)
    if not is_on_curve(point, b2):
        raise ValueError("Decompressed point is not on the curve.")
    return PublicKey(point)

# --- Hash-to-Field (expand message to 96 bytes using DST and keccak256) ---
def _expand_msg_to_96(domain: bytes, message: bytes) -> bytes:
    # Domain length must be 1 <= len(DST) <= 255 (per RFC 9380 and audit guidelines):contentReference[oaicite:3]{index=3}
    dst_len = len(domain)
    if dst_len == 0 or dst_len > 255:
        raise ValueError(f"DST length must be between 1 and 255 bytes (got {dst_len}).")
    DST_prime = domain + bytes([dst_len])
    # 136 zero bytes for Keccak-256 padding (block size 136 bytes for 136*8 = 1088-bit rate)
    z_pad = bytes(136)
    # 96-byte output length in big-endian 2-byte format:
    len_in_bytes = (96).to_bytes(2, 'big')  # = b'\x00\x60'
    # Compute b0 = keccak256(z_pad || message || len_in_bytes || 0x00 || DST_prime)
    k0 = keccak.new(digest_bits=256)
    k0.update(z_pad + message + len_in_bytes + b'\x00' + DST_prime)
    b0 = k0.digest()
    # b1 = keccak256(b0 || 0x01 || DST_prime)
    k1 = keccak.new(digest_bits=256)
    k1.update(b0 + b'\x01' + DST_prime)
    b1 = k1.digest()
    # b2 = keccak256((b0 XOR b1) || 0x02 || DST_prime)
    xor_b0_b1 = bytes(x ^ y for x, y in zip(b0, b1))
    k2 = keccak.new(digest_bits=256)
    k2.update(xor_b0_b1 + b'\x02' + DST_prime)
    b2 = k2.digest()
    # b3 = keccak256((b0 XOR b2) || 0x03 || DST_prime)
    xor_b0_b2 = bytes(x ^ y for x, y in zip(b0, b2))
    k3 = keccak.new(digest_bits=256)
    k3.update(xor_b0_b2 + b'\x03' + DST_prime)
    b3 = k3.digest()
    # Concatenate b1 || b2 || b3 -> 96 bytes
    return b1 + b2 + b3

def _hash_to_field(domain: bytes, message: bytes) -> Tuple[int, int]:
    uniform_bytes = _expand_msg_to_96(domain, message)
    # Split 96 bytes into two 48-byte chunks, convert to integers mod p (field modulus)
    u0 = int.from_bytes(uniform_bytes[:48], 'big') % p
    u1 = int.from_bytes(uniform_bytes[48:], 'big') % p
    return u0, u1

# --- Map-to-Curve (Simplified SWU for BN254 G1) ---
def _map_to_g1(u: int) -> PointG1:
    # Ensure u is a valid field element
    if u < 0 or u >= p:
        raise ValueError("Field element out of range")
    # Curve parameters for E: y^2 = x^3 + 3 over F_p (BN254)
    A, B, Z = 0, 3, 1
    # Constants from Solidity BLS.sol (for Z=1): C1=4, C2 = -1/2 mod p, etc.
    C1 = FQ(4)
    C2 = FQ((p - 1) // 2)  # (p-1)/2 mod p, since -Z/2 = -1/2 mod p
    # Compute helper constants C3 and C4 as in BLS.sol
    neg_gZ = -((Z**3 + B) % p) % p            # -g(Z) mod p
    denom = (3 * Z * Z + 4 * A) % p           # (3*Z^2 + 4A) mod p
    # C3 = sqrt(neg_gZ * denom) with even parity (sgn0(C3)=0)
    c3_val = pow((neg_gZ * denom) % p, (p + 1)//4, p)
    if c3_val % 2 == 1:
        c3_val = p - c3_val  # enforce even parity
    C3 = FQ(c3_val)
    # C4 = 4 * neg_gZ * inv(denom) mod p
    inv_denom = pow(denom, p - 2, p)
    C4 = FQ((4 * neg_gZ * inv_denom) % p)
    # Compute map steps
    u_fq = FQ(u)
    tv1 = u_fq * u_fq * C1        # tv1 = u^2 * 4
    tv2 = FQ(1) + tv1            # tv2 = 1 + tv1
    tv1 = FQ(1) - tv1            # tv1 = 1 - tv1
    tv3 = tv1 * tv2             # tv3 = (1 - tv1) * (1 + tv1) = 1 - tv1^2 (nonzero unless u^2*4 = ±1)
    tv3_inv = _inv_fq(tv3)      # invert(tv3)
    # Compute candidates x-coordinates
    tv5 = u_fq * tv1 * tv3_inv * C3  # tv5 = u * tv1 * tv3_inv * C3
    x1 = C2 - tv5
    x2 = C2 + tv5
    tv7 = tv2 * tv2
    tv8 = tv7 * tv3_inv
    x3 = FQ(Z) + C4 * (tv8 * tv8)
    # Evaluate curve equation y^2 = x^3 + B for each candidate x
    gx1 = x1 * x1 * x1 + FQ(B)
    gx2 = x2 * x2 * x2 + FQ(B)
    gx3 = x3 * x3 * x3 + FQ(B)
    # Try x1
    try:
        y = _sqrt_fq(gx1)
        x = x1
    except ValueError:
        # If g(x1) not square, try x2
        try:
            y = _sqrt_fq(gx2)
            x = x2
        except ValueError:
            # Otherwise use x3 (guaranteed to be square)
            y = _sqrt_fq(gx3)
            x = x3
    # Ensure y has the correct sign (sign of y matches sign of u):contentReference[oaicite:4]{index=4}
    if (u % 2) != (y.n % 2):  # using FQ.n to get integer value
        y = -y
    return (x, y)

# --- Public Hash-to-G1 API ---
def hash_to_g1(msg: bytes, domain: bytes) -> PointG1:
    """
    Hash a message to a point on BN254 G1 using the same algorithm as BLS.sol.
    """
    u0, u1 = _hash_to_field(domain, msg)
    P0 = _map_to_g1(u0)
    P1 = _map_to_g1(u1)
    P = add(P0, P1)  # add the two points on G1
    # Validate the result is on curve (should always be, given construction)
    if not is_on_curve(P, b):
        raise ValueError("hash_to_g1 produced point not on curve")
    return P

# --- BLS Signature Functions ---
def sign(msg: bytes, sk: SecretKey, domain: bytes) -> Signature:
    """
    Sign the message by hashing to G1 with the given domain, then multiplying by sk.
    """
    h = hash_to_g1(msg, domain)
    sig_point = multiply(h, sk)
    return Signature(sig_point)

def verify_single(pk: PublicKey, sig: Signature, msg: bytes, domain: bytes) -> bool:
    """
    Verify a single BLS signature against the message and domain.
    """
    h = hash_to_g1(msg, domain)
    # Pairing check: e(sig, G2) ?= e(h, pk)
    lhs = pairing(G2, sig)
    rhs = pairing(pk, h)
    return final_exponentiate(lhs) == final_exponentiate(rhs)

def aggregate_pks(pks: List[PublicKey]) -> PublicKey:
    if not pks:
        return Z2
    return PublicKey(add(pks[0], aggregate_pks(pks[1:]))) if len(pks) > 1 else pks[0]

def aggregate_sigs(sigs: List[Signature]) -> Signature:
    if not sigs:
        return Z1
    return Signature(add(sigs[0], aggregate_sigs(sigs[1:]))) if len(sigs) > 1 else sigs[0]

def verify_aggregate(pks: List[PublicKey], sig_agg: Signature, msgs: List[bytes], domain: bytes) -> bool:
    if len(pks) != len(msgs):
        raise ValueError("Number of public keys and messages must be equal.")
    lhs = pairing(G2, sig_agg)
    rhs = FQ12.one()
    for pk, msg in zip(pks, msgs):
        h = hash_to_g1(msg, domain)
        rhs *= pairing(pk, h)
    return final_exponentiate(lhs) == final_exponentiate(rhs)

def verify_fast_aggregate_same_msg(pks: List[PublicKey], sig_agg: Signature, msg: bytes, domain: bytes) -> bool:
    pk_agg = aggregate_pks(pks)
    h = hash_to_g1(msg, domain)
    lhs = pairing(G2, sig_agg)
    rhs = pairing(pk_agg, h)
    return final_exponentiate(lhs) == final_exponentiate(rhs)

# --- Internal helpers (unchanged) ---
def _pair(z: FQ2) -> Tuple[int, int]:
    a, b = z.coeffs
    return int(getattr(a, "n", a)), int(getattr(b, "n", b))

def _sgn0(z: FQ2) -> int:
    a, b = _pair(z)
    return (b & 1) if b != 0 else (a & 1)

def _inv_fq(x: FQ) -> FQ:
    n = x.n
    if n == 0:
        raise ZeroDivisionError("Cannot invert zero.")
    return FQ(pow(n, p - 2, p))

def _sqrt_fq(n_fq: FQ) -> FQ:
    n = n_fq.n
    if n == 0:
        return FQ.zero()
    # Check quadratic residuosity via Euler's criterion
    if pow(n, (p - 1) // 2, p) != 1:
        raise ValueError("Not a quadratic residue")
    # BN254 prime p ≡ 3 (mod 4), so we can compute sqrt as n^((p+1)//4)
    root = FQ(pow(n, (p + 1) // 4, p))
    # Ensure we got the correct root (could be either ±root)
    if (root * root) != n_fq:
        raise ValueError("Failed to compute square root")
    return root

def _sqrt_fq2(v: FQ2) -> FQ2:
    if v == FQ2.zero():
        return FQ2.zero()
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