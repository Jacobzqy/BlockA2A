# test_bn256_pytest.py
import pytest
import os
from src.blocka2a.utils import bn256
from py_ecc.bn128 import G1, G2, Z1, Z2, is_on_curve, b, b2, add, multiply, curve_order


# --- Pytest Fixtures ---
# Fixtures 提供一个固定的基线，`scope="module"` 表示它们在每个模块中只创建一次。

@pytest.fixture(scope="module")
def domain():
    """提供一个标准的域分隔符 (DST) 用于测试。"""
    return b"BLS_SIG_BN254_PYTEST_V1"


@pytest.fixture(scope="module")
def messages():
    """提供一组标准的消息用于测试。"""
    return {
        "msg1": b"Hello, world!",
        "msg2": b"This is a test message.",
        "msg3": b"Another message for aggregation."
    }


@pytest.fixture(scope="module")
def keypair1():
    """提供第一个预生成的密钥对。"""
    return bn256.generate_keypair()


@pytest.fixture(scope="module")
def keypair2():
    """提供第二个预生成的密钥对。"""
    return bn256.generate_keypair()


@pytest.fixture(scope="module")
def keypair3():
    """提供第三个预生成的密钥对。"""
    return bn256.generate_keypair()


# --- 测试类 ---
# 使用类来组织相关的测试，使结构更清晰。

class TestBN256:

    def test_key_generation(self):
        """测试 generate_keypair 函数。"""
        sk, pk = bn256.generate_keypair()
        assert isinstance(sk, int)
        assert isinstance(pk, tuple)
        # 检查私钥是否在有效范围内
        assert 1 <= sk < curve_order
        # 检查公钥是否在 G2 曲线上
        assert is_on_curve(pk, b2)
        # 验证 pk = sk * G2
        expected_pk = multiply(G2, sk)
        assert pk == expected_pk

    def test_g2_compression_decompression(self, keypair1):
        """测试 G2 点压缩和解压缩的往返一致性。"""
        _, pk1 = keypair1
        compressed_pk = bn256.compress_g2(pk1)
        assert isinstance(compressed_pk, bytes)
        assert len(compressed_pk) == 64
        decompressed_pk = bn256.decompress_g2(compressed_pk)
        assert pk1 == decompressed_pk

    def test_g2_compression_infinity(self):
        """测试无穷远点的压缩和解压缩。"""
        compressed_z2 = bn256.compress_g2(Z2)
        assert compressed_z2 == bytes([0xc0]) + bytes(63)
        decompressed_z2 = bn256.decompress_g2(compressed_z2)
        assert Z2 == decompressed_z2

    def test_g2_decompression_invalid(self, keypair1):
        """测试 G2 解压缩的无效输入。"""
        _, pk1 = keypair1
        with pytest.raises(ValueError, match="Input must be 64 bytes"):
            bn256.decompress_g2(bytes(63))

        with pytest.raises(ValueError, match="Compression bit is not set"):
            invalid_bytes = bytearray(bn256.compress_g2(pk1))
            invalid_bytes[0] &= 0x7F  # 清除压缩标志位
            bn256.decompress_g2(bytes(invalid_bytes))

    def test_hash_to_g1(self, messages, domain):
        """测试 hash_to_g1 函数的正确性和确定性。"""
        msg1, msg2 = messages["msg1"], messages["msg2"]

        h1 = bn256.hash_to_g1(msg1, domain)
        assert is_on_curve(h1, b), "哈希结果必须在 G1 曲线上"

        h1_again = bn256.hash_to_g1(msg1, domain)
        assert h1 == h1_again, "相同输入的哈希结果必须相同"

        h2 = bn256.hash_to_g1(msg2, domain)
        assert h1 != h2, "不同消息的哈希结果必须不同"

        h3 = bn256.hash_to_g1(msg1, b"DIFFERENT_DOMAIN")
        assert h1 != h3, "不同域的哈希结果必须不同"

    def test_dst_validation(self, messages):
        """测试哈希函数中域分隔符 (DST) 的长度验证。"""
        msg1 = messages["msg1"]
        with pytest.raises(ValueError, match="DST length must be between 1 and 255 bytes"):
            bn256.hash_to_g1(msg1, b"")  # DST 过短

        with pytest.raises(ValueError, match="DST length must be between 1 and 255 bytes"):
            bn256.hash_to_g1(msg1, os.urandom(256))  # DST 过长

    def test_sign_verify_single(self, keypair1, messages, domain):
        """测试一个有效的单一签名和验证流程。"""
        sk1, pk1 = keypair1
        msg1 = messages["msg1"]

        sig = bn256.sign(msg1, sk1, domain)
        assert isinstance(sig, tuple)
        assert bn256.verify_single(pk1, sig, msg1, domain), "有效签名必须验证通过"

    def test_verify_single_invalid(self, keypair1, keypair2, messages, domain):
        """测试无效的单一签名无法通过验证。"""
        sk1, pk1 = keypair1
        _, pk2 = keypair2
        msg1, msg2 = messages["msg1"], messages["msg2"]

        sig = bn256.sign(msg1, sk1, domain)

        assert not bn256.verify_single(pk2, sig, msg1, domain), "使用错误的公钥必须验证失败"
        assert not bn256.verify_single(pk1, sig, msg2, domain), "使用错误的消息必须验证失败"
        assert not bn256.verify_single(pk1, sig, msg1, b"WRONG_DOMAIN"), "使用错误的域必须验证失败"

        tampered_sig = bn256.Signature(add(sig, G1))
        assert not bn256.verify_single(pk1, tampered_sig, msg1, domain), "篡改后的签名必须验证失败"

    def test_aggregation(self, keypair1, keypair2, keypair3, messages, domain):
        """测试公钥和签名的聚合功能。"""
        keys = {"sk1": keypair1[0], "pk1": keypair1[1], "sk2": keypair2[0], "pk2": keypair2[1], "sk3": keypair3[0],
                "pk3": keypair3[1]}

        pks = [keys["pk1"], keys["pk2"], keys["pk3"]]
        sig1 = bn256.sign(messages["msg1"], keys["sk1"], domain)
        sig2 = bn256.sign(messages["msg2"], keys["sk2"], domain)
        sig3 = bn256.sign(messages["msg3"], keys["sk3"], domain)
        sigs = [sig1, sig2, sig3]

        # 测试公钥聚合
        agg_pk = bn256.aggregate_pks(pks)
        manual_agg_pk = add(add(keys["pk1"], keys["pk2"]), keys["pk3"])
        assert agg_pk == manual_agg_pk
        assert bn256.aggregate_pks([]) == Z2, "空公钥列表的聚合应返回 G2 的无穷远点"

        # 测试签名聚合
        agg_sig = bn256.aggregate_sigs(sigs)
        manual_agg_sig = add(add(sig1, sig2), sig3)
        assert agg_sig == manual_agg_sig
        assert bn256.aggregate_sigs([]) == Z1, "空签名列表的聚合应返回 G1 的无穷远点"

    def test_verify_aggregate(self, keypair1, keypair2, keypair3, messages, domain):
        """测试对不同消息的聚合签名进行验证。"""
        sks = [keypair1[0], keypair2[0], keypair3[0]]
        pks = [keypair1[1], keypair2[1], keypair3[1]]
        msgs = [messages["msg1"], messages["msg2"], messages["msg3"]]

        sigs = [bn256.sign(m, sk, domain) for m, sk in zip(msgs, sks)]
        agg_sig = bn256.aggregate_sigs(sigs)

        assert bn256.verify_aggregate(pks, agg_sig, msgs, domain), "有效聚合签名必须验证通过"

        # 测试消息列表顺序错误
        wrong_msgs = [msgs[0], msgs[2], msgs[1]]
        assert not bn256.verify_aggregate(pks, agg_sig, wrong_msgs, domain)

        # 测试公钥列表顺序错误
        wrong_pks = [pks[0], pks[2], pks[1]]
        assert not bn256.verify_aggregate(wrong_pks, agg_sig, msgs, domain)

        # 测试公钥和消息数量不匹配
        with pytest.raises(ValueError, match="Number of public keys and messages must be equal"):
            bn256.verify_aggregate(pks, agg_sig, msgs[:2], domain)

    def test_verify_fast_aggregate_same_msg(self, keypair1, keypair2, keypair3, messages, domain):
        """测试对相同消息的快速聚合签名进行验证。"""
        sks = [keypair1[0], keypair2[0], keypair3[0]]
        pks = [keypair1[1], keypair2[1], keypair3[1]]
        msg1, msg2 = messages["msg1"], messages["msg2"]

        # 所有参与方对同一消息签名
        sigs = [bn256.sign(msg1, sk, domain) for sk in sks]
        agg_sig = bn256.aggregate_sigs(sigs)

        assert bn256.verify_fast_aggregate_same_msg(pks, agg_sig, msg1, domain), "快速聚合签名必须验证通过"

        # 使用错误的消息进行验证
        assert not bn256.verify_fast_aggregate_same_msg(pks, agg_sig, msg2, domain)

        # 聚合签名中包含一个对不同消息的签名
        wrong_sigs = [
            bn256.sign(msg1, sks[0], domain),
            bn256.sign(msg2, sks[1], domain),  # 这个签名是针对不同消息的
            bn256.sign(msg1, sks[2], domain),
        ]
        wrong_agg_sig = bn256.aggregate_sigs(wrong_sigs)
        assert not bn256.verify_fast_aggregate_same_msg(pks, wrong_agg_sig, msg1, domain)