import pytest
import multibase  # 导入以构造无效前缀的测试用例
from src.blocka2a.utils import crypto

# 导入底层 bn256 库以进行更深入的往返验证
from src.blocka2a.utils import bn256 as bls_bn256
from py_ecc.bn128 import FQ, FQ2, G2, multiply


# --- 已有测试用例 (无改动) ---

def test_gen_ed25519_format():
    """测试 Ed25519 密钥生成函数的输出格式"""
    key_pair = crypto.gen_ed25519()
    assert isinstance(key_pair, dict)
    assert set(key_pair.keys()) == {
        "private_key_hex", "public_key_hex", "public_key_multibase"
    }
    # Ed25519 私钥种子是 32 字节, 公钥是 32 字节
    assert len(key_pair["private_key_hex"]) == 64
    assert len(key_pair["public_key_hex"]) == 64
    assert key_pair["public_key_multibase"].startswith('z')


def test_gen_bls12_381_g2_format():
    """测试 BLS12-381/G2 密钥生成函数的输出格式"""
    key_pair = crypto.gen_bls12_381_g2()
    assert isinstance(key_pair, dict)
    assert set(key_pair.keys()) == {
        "private_key_int", "private_key_hex", "public_key_hex", "public_key_multibase"
    }
    # 压缩公钥是 96 字节
    assert len(key_pair["public_key_hex"]) == 192
    assert key_pair["public_key_multibase"].startswith('z')


def test_bls12_381_g2_pubkey_to_coords():
    """测试 BLS12-381 G2 坐标转换函数"""
    key_pair = crypto.gen_bls12_381_g2()
    coords = crypto.bls12_381_g2_pubkey_to_coords(key_pair["public_key_hex"])
    assert isinstance(coords, dict)
    assert set(coords.keys()) == {"x_r", "x_i", "y_r", "y_i"}
    assert all(isinstance(v, int) for v in coords.values())


def test_gen_bn256_g2_format():
    """测试新增的 BN256/G2 密钥生成函数的输出格式"""
    key_pair = crypto.gen_bn256_g2()
    assert isinstance(key_pair, dict)
    assert set(key_pair.keys()) == {
        "private_key_int", "private_key_hex", "public_key_hex", "public_key_multibase"
    }
    # 压缩公钥是 64 字节
    assert len(key_pair["public_key_hex"]) == 128
    assert key_pair["public_key_multibase"].startswith('z')


def test_bn256_g2_pubkey_to_coords_and_roundtrip():
    """
    测试 BN256 G2 坐标转换，并进行关键的往返验证。
    确保从坐标可以重构出原始公钥。
    """
    # 1. 使用底层库生成一个原始密钥对
    sk, pk = bls_bn256.generate_keypair()

    # 2. 使用待测模块的压缩和坐标转换功能
    pk_bytes = bls_bn256.compress_g2(pk)
    coords = crypto.bn256_g2_pubkey_to_coords(pk_bytes)

    # 3. 验证输出格式
    assert isinstance(coords, dict)
    assert set(coords.keys()) == {"x_r", "x_i", "y_r", "y_i"}
    assert all(isinstance(v, int) for v in coords.values())

    # 4. 关键：从坐标重构 FQ2 点，并与原始公钥比较
    x_reconstructed = FQ2([coords["x_r"], coords["x_i"]])
    y_reconstructed = FQ2([coords["y_r"], coords["y_i"]])
    pk_reconstructed = (x_reconstructed, y_reconstructed)

    assert pk == pk_reconstructed, "从坐标重构的公钥与原始公钥不匹配"


def test_generate_key_sets():
    """测试批量生成函数"""
    count = 2
    key_sets = crypto.generate_key_sets(count)

    assert isinstance(key_sets, list)
    assert len(key_sets) == count

    first_set = key_sets[0]
    assert isinstance(first_set, dict)
    assert "set" in first_set
    assert "ed25519" in first_set
    assert "bls12_381_g2" in first_set
    assert "bn256_g2" in first_set
    assert "g2_affine_coords" in first_set["bls12_381_g2"]
    assert "g2_affine_coords" in first_set["bn256_g2"]


def test_ed25519_sign_verify_end_to_end():
    """对模块中的 Ed25519 签名和验证流程进行端到端测试"""
    # 1. 生成密钥
    key_pair = crypto.gen_ed25519()
    priv_key_hex = key_pair["private_key_hex"]
    pub_key_hex = key_pair["public_key_hex"]

    # 2. 准备签名参数
    message = "This is a test message for Ed25519 signature."
    verification_method = "did:example:123#keys-1"

    # 3. 签名 (直接使用32字节的私钥)
    proof = crypto.sign(
        message,
        bytes.fromhex(priv_key_hex),  # 将32字节的hex私钥转换为bytes
        "Ed25519Signature2020",
        verification_method
    )

    # 4. 验证 (肯定性测试)
    is_valid = crypto.verify(proof, message, pub_key_hex)
    assert is_valid is True, "有效的签名未能通过验证"

    # 5. 验证 (否定性测试)
    is_invalid = crypto.verify(proof, "a different message", pub_key_hex)
    assert is_invalid is False, "使用错误消息的验证应失败"

# --- 新增的测试用例 ---

def test_multibase_to_raw_public_key():
    """
    测试 multibase 解码和针对所有支持的密钥类型进行前缀剥离的功能。
    """
    # 场景 1: 测试 Ed25519 密钥
    ed_keys = crypto.gen_ed25519()
    raw_ed_pk = crypto.multibase_to_raw_public_key(ed_keys["public_key_multibase"])
    assert raw_ed_pk.hex() == ed_keys["public_key_hex"]
    assert len(raw_ed_pk) == 32

    # 场景 2: 测试 BLS12-381 密钥
    bls_keys = crypto.gen_bls12_381_g2()
    raw_bls_pk = crypto.multibase_to_raw_public_key(bls_keys["public_key_multibase"])
    assert raw_bls_pk.hex() == bls_keys["public_key_hex"]
    assert len(raw_bls_pk) == 96

    # 场景 3: 测试 BN256 密钥
    bn256_keys = crypto.gen_bn256_g2()
    raw_bn256_pk = crypto.multibase_to_raw_public_key(bn256_keys["public_key_multibase"])
    assert raw_bn256_pk.hex() == bn256_keys["public_key_hex"]
    assert len(raw_bn256_pk) == 64

    # 场景 4: 测试未知的 multicodec 前缀
    unknown_prefix = b'\xff\xee'
    # 使用一个真实的密钥数据，但加上一个伪造的前缀
    raw_key_data = bytes.fromhex(ed_keys["public_key_hex"])
    fake_multibase_str = multibase.encode("base58btc", unknown_prefix + raw_key_data).decode('ascii')

    with pytest.raises(ValueError, match="Unknown multicodec prefix"):
        crypto.multibase_to_raw_public_key(fake_multibase_str)

    # 场景 5: 测试格式错误的非 multibase 字符串
    with pytest.raises(ValueError):
        # 这个字符串没有以有效的 multibase 前缀字符（如 'z'）开头
        crypto.multibase_to_raw_public_key("this_is_not_a_multibase_string")