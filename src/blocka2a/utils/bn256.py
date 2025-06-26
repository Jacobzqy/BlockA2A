"""Implements the BLS signature scheme over the BN254 elliptic curve.

This module provides a comprehensive set of functions for generating keys,
signing messages, and verifying signatures using the Boneh-Lynn-Shacham (BLS)
signature scheme. The implementation is tailored for the BN254 pairing-friendly
curve, with signatures on G1 and public keys on G2.

It adheres to modern cryptographic practices, including a hash-to-curve
mechanism based on RFC 9380 and the Simplified
SWU mapping algorithm.

Key Features:
  - Key generation, signing, and verification.
  - Aggregation of signatures and public keys.
  - Verification of aggregated signatures for both distinct and common messages.
  - Serialization (compression/decompression) of G2 points (public keys).
"""
from __future__ import annotations
import secrets
from typing import List, NewType, Tuple
from py_ecc.bn128 import (
    FQ, FQ2, FQ12,
    G2, Z1, Z2,
    b, b2, curve_order,
    add, multiply, pairing, final_exponentiate, is_on_curve,
    field_modulus as p
)
from Crypto.Hash import keccak

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
    """Generates a cryptographically secure BLS key pair.

    The secret key is a random integer in the range [1, curve_order-1].
    The public key is derived by multiplying the G2 generator point by the
    secret key.

    Returns:
        A tuple containing the generated SecretKey and PublicKey.
    """
    secret_key = secrets.randbelow(curve_order - 1) + 1
    public_key = multiply(G2, secret_key)
    return SecretKey(secret_key), PublicKey(public_key)

# --- G2 Point Compression/Decompression ---

def compress_g2(pk: PublicKey) -> bytes:
    """Serializes a G2 point (public key) into a 64-byte compressed format.

    This compression scheme follows the IETF BLS signature draft specification.
    The first few bits of the output encode metadata:
      - 0xc0 prefix indicates the point at infinity.
      - 0x80 bit indicates that the point is compressed.
      - 0x40 bit indicates the sign of the y-coordinate for recovery.

    Args:
        pk: The PublicKey (a G2 point) to compress.

    Returns:
        A 64-byte bytes object representing the compressed point.
    """
    if pk is None or pk == Z2:
        # Standard encoding for the point at infinity.
        return bytes([0xc0]) + bytes(63)
    x_pair = _pair(pk[0])
    raw = x_pair[0].to_bytes(32, "big") + x_pair[1].to_bytes(32, "big")

    # Set the compression flag (most significant bit).
    first_byte = raw[0] | 0x80
    if _sgn0(pk[1]):
        first_byte |= 0x40
    return bytes([first_byte]) + raw[1:]


def decompress_g2(buf: bytes) -> PublicKey:
    """Deserializes a 64-byte compressed G2 point back into a PublicKey.

    This function reverses the compress_g2 operation, reconstructing the
    y-coordinate from the x-coordinate and the sign bit.

    Args:
        buf: A 64-byte bytes object of a compressed G2 point.

    Returns:
        The decompressed PublicKey (a G2 point).

    Raises:
        ValueError: If the input buffer is not 64 bytes, if the compression
            bit is not set, or if the resulting point is not on the G2 curve.
    """
    if len(buf) != 64:
        raise ValueError("Input must be 64 bytes.")
    # Check for the point at infinity encoding.
    if buf == (bytes([0xc0]) + bytes(63)):
        return Z2
    # The compression bit must be set for a valid point.
    if not (buf[0] & 0x80):
        raise ValueError("Compression bit is not set.")

    # Extract sign and recover x-coordinate bytes by masking out flag bits.
    sign_bit = (buf[0] & 0x40) >> 6
    x_byte_0 = buf[0] & 0x3F
    x_bytes = bytes([x_byte_0]) + buf[1:]

    # Reconstruct the FQ2 element for the x-coordinate.
    x1 = int.from_bytes(x_bytes[:32], "big")
    x2 = int.from_bytes(x_bytes[32:], "big")
    x = FQ2([x1, x2])

    # Solve the curve equation y^2 = x^3 + b2 to find the y-coordinate.
    y_squared = x ** 3 + b2
    y = _sqrt_fq2(y_squared)
    if _sgn0(y) != sign_bit:
        y = -y

    point = (x, y)
    if not is_on_curve(point, b2):
        raise ValueError("Decompressed point is not on the curve.")
    return PublicKey(point)


# --- Hash-to-Curve Internals ---

def _expand_msg_to_96(domain: bytes, message: bytes) -> bytes:
    """Expands a message to 96 bytes using expand_message_xmd with Keccak-256.

    This is the first step of the hash-to-curve procedure, as specified in
    RFC 9380. It generates a uniformly random byte string from a message and
    a domain separation tag.

    Args:
        domain: The domain separation tag (DST), 1-255 bytes long.
        message: The input message to hash.

    Returns:
        A 96-byte bytes object.

    Raises:
        ValueError: If the DST length is invalid.
    """
    dst_len = len(domain)
    if dst_len == 0 or dst_len > 255:
        raise ValueError(f"DST length must be between 1 and 255 bytes (got {dst_len}).")
    dst_prime = domain + bytes([dst_len])
    z_pad = bytes(136) # Keccak-256 block size.
    len_in_bytes = (96).to_bytes(2, 'big')

    # b0 = H(z_pad || message || len_in_bytes || 0x00 || dst_prime)
    k0 = keccak.new(digest_bits=256)
    k0.update(z_pad + message + len_in_bytes + b'\x00' + dst_prime)
    b0 = k0.digest()

    # b1 = H(b0 || 0x01 || dST_prime)
    k1 = keccak.new(digest_bits=256)
    k1.update(b0 + b'\x01' + dst_prime)
    b1 = k1.digest()

    # b2 = H(strxor(b_0, b_1) || I2OSP(2, 1) || dst_prime)
    xor_b0_b1 = bytes(x ^ y for x, y in zip(b0, b1))
    k2 = keccak.new(digest_bits=256)
    k2.update(xor_b0_b1 + b'\x02' + dst_prime)
    b2 = k2.digest()

    # b3 = H(strxor(b_0, b_2) || I2OSP(3, 1) || dst_prime)
    xor_b0_b2 = bytes(x ^ y for x, y in zip(b0, b2))
    k3 = keccak.new(digest_bits=256)
    k3.update(xor_b0_b2 + b'\x03' + dst_prime)
    b3 = k3.digest()

    # Concatenate the three blocks to get the required 96 bytes.
    return b1 + b2 + b3


def _hash_to_field(domain: bytes, message: bytes) -> Tuple[int, int]:
    """Hashes a message to two field elements for curve mapping."""
    uniform_bytes = _expand_msg_to_96(domain, message)
    # Each G1 point is constructed from two field elements (u0, u1).
    u0 = int.from_bytes(uniform_bytes[:48], 'big') % p
    u1 = int.from_bytes(uniform_bytes[48:], 'big') % p
    return u0, u1


def _map_to_g1(u: int) -> PointG1:
    """Maps a field element to a point on G1 using Simplified SWU.

    This implements the Simplified Shallue-van de Woestijne-Ulas (SWU)
    isogeny map for the BN254 curve (y^2 = x^3 + 3).

    Args:
        u: A field element (integer modulo p).

    Returns:
        A valid PointG1 on the curve.

    Raises:
        ValueError: If u is outside the valid field range.
    """
    if u < 0 or u >= p:
        raise ValueError("Field element out of range")
    # Curve and map parameters for y^2 = x^3 + 3, with Z=1.
    a, b, z = 0, 3, 1
    c1 = FQ(4)
    c2 = FQ((p - 1) // 2)  # -1/2 mod p

    # Precomputed constants for the SWU map.
    neg_gz = -((z**3 + b) % p) % p
    denom = (3 * z * z + 4 * a) % p
    c3_val = pow((neg_gz * denom) % p, (p + 1)//4, p)
    if c3_val % 2 == 1:
        c3_val = p - c3_val  # Enforce even parity for determinism.
    c3 = FQ(c3_val)
    inv_denom = pow(denom, p - 2, p)
    c4 = FQ((4 * neg_gz * inv_denom) % p)

    # Simplified SWU algorithm steps.
    u_fq = FQ(u)
    tv1 = u_fq * u_fq * c1
    tv2 = FQ(1) + tv1
    tv1 = FQ(1) - tv1
    tv3 = tv1 * tv2
    tv3_inv = _inv_fq(tv3)
    tv5 = u_fq * tv1 * tv3_inv * c3
    x1 = c2 - tv5
    x2 = c2 + tv5
    tv7 = tv2 * tv2
    tv8 = tv7 * tv3_inv
    x3 = FQ(z) + c4 * (tv8 * tv8)

    # Find the first valid x-coordinate that is a quadratic residue.
    gx1 = x1 * x1 * x1 + FQ(b)
    gx2 = x2 * x2 * x2 + FQ(b)
    gx3 = x3 * x3 * x3 + FQ(b)
    try:
        y = _sqrt_fq(gx1)
        x = x1
    except ValueError:
        try:
            y = _sqrt_fq(gx2)
            x = x2
        except ValueError:
            y = _sqrt_fq(gx3) # This is guaranteed to be a square.
            x = x3

    # Ensure the sign of y matches the sign of u for determinism.
    if (u % 2) != (y.n % 2):  # using FQ.n to get integer value
        y = -y
    return x, y

# --- Public Hash-to-G1 API ---

def hash_to_g1(msg: bytes, domain: bytes) -> PointG1:
    """Hashes a message to a point on the BN254 G1 curve.

    This function serves as the public API for the hash-to-curve-suite.
    It combines hashing to a field with mapping to the curve.

    Args:
        msg: The message to hash.
        domain: The domain separation tag.

    Returns:
        A PointG1 representing the hash of the message.
    """
    u0, u1 = _hash_to_field(domain, msg)
    p0 = _map_to_g1(u0)
    p1 = _map_to_g1(u1)
    # The final point is the sum of two mapped points.
    p = add(p0, p1)
    if not is_on_curve(p, b):
        # This check should not fail if the map is correct.
        raise ValueError("hash_to_g1 produced point not on curve")
    return p

# --- BLS Signature Core Functions ---

def sign(msg: bytes, sk: SecretKey, domain: bytes) -> Signature:
    """Creates a BLS signature for a given message.

    The signature is the message hash (a G1 point) multiplied by the secret key.

    Args:
        msg: The message to be signed.
        sk: The `SecretKey` of the signer.
        domain: The domain separation tag, critical for security.

    Returns:
        A Signature object.
    """
    h = hash_to_g1(msg, domain)
    sig_point = multiply(h, sk)
    return Signature(sig_point)


def deserialize_g1(buf: bytes) -> Signature:
    """
    反序列化一个64字节的未压缩G1点。
    这是您签名流程的精确反向操作。
    """
    # 步骤1: 检查输入是否为64字节
    if len(buf) != 64:
        raise ValueError(f"Signature must be 64 bytes, but got {len(buf)}")

    # 步骤2 & 4: 切分字节并转换为整数
    x = int.from_bytes(buf[0:32], "big")
    y = int.from_bytes(buf[32:64], "big")

    # 步骤5 & 6: 构造成 py_ecc 能理解的点对象
    point = (FQ(x), FQ(y))

    # 安全检查：确保这个点确实在曲线上
    if not is_on_curve(point, b):
        raise ValueError("Deserialized signature point is not on the G1 curve")

    # 用您的 Signature 类型包装后返回
    return Signature(point)


def verify_single(pk: PublicKey, sig: Signature, msg: bytes, domain: bytes) -> bool:
    """Verifies a single BLS signature.

    The verification is successful if the pairing equation holds:
    e(sig, G2_generator) == e(hash(msg), pk)

    Args:
        pk: The PublicKey of the signer.
        sig: The Signature to be verified.
        msg: The message that was signed.
        domain: The domain separation tag used during signing.

    Returns:
        True if the signature is valid, False otherwise.
    """
    h = hash_to_g1(msg, domain)
    # Left-hand side of the pairing equation.
    lhs = pairing(G2, sig)
    # Right-hand side of the pairing equation.
    rhs = pairing(pk, h)
    # The final check requires final exponentiation.
    return final_exponentiate(lhs) == final_exponentiate(rhs)


def aggregate_pks(pks: List[PublicKey]) -> PublicKey:
    """Aggregates a list of public keys into a single public key.

    Aggregation is performed by adding the G2 points of the public keys.

    Args:
        pks: A list of PublicKey objects.

    Returns:
        The single, aggregated PublicKey. Returns the G2 identity point if
        the input list is empty.
    """
    if not pks:
        return Z2
    return PublicKey(add(pks[0], aggregate_pks(pks[1:]))) if len(pks) > 1 else pks[0]


def aggregate_sigs(sigs: List[Signature]) -> Signature:
    """Aggregates a list of signatures into a single signature.

    Aggregation is performed by adding the G1 points of the signatures.

    Args:
        sigs: A list of Signature objects.

    Returns:
        The single, aggregated Signature. Returns the G1 identity point if
        the input list is empty.
    """
    if not sigs:
        return Z1
    return Signature(add(sigs[0], aggregate_sigs(sigs[1:]))) if len(sigs) > 1 else sigs[0]


def verify_aggregate(pks: List[PublicKey], sig_agg: Signature, msgs: List[bytes], domain: bytes) -> bool:
    """Verifies an aggregated signature where each signer signed a distinct message.

    The verification check is:
    e(sig_agg, G2_generator) == product(e(hash(msg_i), pk_i))

    Args:
        pks: The list of PublicKey objects from the signers.
        sig_agg: The aggregated Signature.
        msgs: The list of distinct messages, one for each public key.
        domain: The domain separation tag.

    Returns:
        True if the signature is valid, False otherwise.

    Raises:
        ValueError: If the number of public keys and messages do not match.
    """
    if len(pks) != len(msgs):
        raise ValueError("Number of public keys and messages must be equal.")
    lhs = pairing(G2, sig_agg)
    rhs = FQ12.one()
    # Accumulate the products of pairings on the right-hand side.
    for pk, msg in zip(pks, msgs):
        h = hash_to_g1(msg, domain)
        rhs *= pairing(pk, h)
    return final_exponentiate(lhs) == final_exponentiate(rhs)


def verify_fast_aggregate_same_msg(pks: List[PublicKey], sig_agg: Signature, msg: bytes, domain: bytes) -> bool:
    """Verifies an aggregated signature where all signers signed the same message.

    This method is more efficient than verify_aggregate as it first aggregates
    the public keys, requiring only two pairing operations. The check is:
    e(sig_agg, G2_generator) == e(hash(msg), pk_agg)

    Args:
        pks: The list of PublicKey objects from the signers.
        sig_agg: The aggregated Signature.
        msg: The single message signed by all participants.
        domain: The domain separation tag.

    Returns:
        True if the signature is valid, False otherwise.
    """
    pk_agg = aggregate_pks(pks)
    h = hash_to_g1(msg, domain)
    lhs = pairing(G2, sig_agg)
    rhs = pairing(pk_agg, h)
    return final_exponentiate(lhs) == final_exponentiate(rhs)


# --- Internal Mathematical Helper Functions ---

def _pair(z: FQ2) -> Tuple[int, int]:
    """Extracts integer coefficients from an FQ2 field element."""
    a, b = z.coeffs
    return int(getattr(a, "n", a)), int(getattr(b, "n", b))


def _sgn0(z: FQ2) -> int:
    """Computes the sgn0 of an FQ2 element for deterministic point compression.

    Returns the sign (0 or 1) based on the parity of the coefficients.
    """
    a, b = _pair(z)
    return (b & 1) if b != 0 else (a & 1)


def _inv_fq(x: FQ) -> FQ:
    """Computes the modular multiplicative inverse in the prime field FQ."""
    n = x.n
    if n == 0:
        raise ZeroDivisionError("Cannot invert zero in a field.")
    # By Fermat's Little Theorem: x^(p-2) mod p.
    return FQ(pow(n, p - 2, p))


def _sqrt_fq(n_fq: FQ) -> FQ:
    """Computes the modular square root in FQ for a prime p === 3 (mod 4)."""
    n = n_fq.n
    if n == 0:
        return FQ.zero()
    if pow(n, (p - 1) // 2, p) != 1:
        raise ValueError("Not a quadratic residue")
    # BN254 prime p ≡ 3 (mod 4), so we can compute sqrt as n^((p+1)//4)
    root = FQ(pow(n, (p + 1) // 4, p))
    # Ensure we got the correct root (could be either ±root)
    if (root * root) != n_fq:
        raise ValueError("Failed to compute square root")
    return root


def _sqrt_fq2(v: FQ2) -> FQ2:
    """Computes the modular square root in the extension field FQ2."""
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