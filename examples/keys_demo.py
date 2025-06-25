import sys
import os
import json

# --- 动态路径设置 ---
# 确保无论从哪里运行此脚本，都能找到我们项目中的 `src` 目录。
try:
    from src.blocka2a.utils import crypto
    from src.blocka2a.utils import bn256 as bls_bn256
except ImportError:
    print("未能直接导入库，正在尝试将项目根目录添加到 Python 路径中...")
    # 获取当前脚本文件所在的目录 (example/)
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # 项目根目录是 example/ 的父目录
    project_root = os.path.abspath(os.path.join(current_dir, '..'))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
        print(f"    已将 '{project_root}' 添加到 sys.path")

    # 再次尝试导入
    try:
        from src.blocka2a.utils import crypto
        from src.blocka2a.utils import bn256 as bls_bn256
    except ImportError as e:
        print("\n错误：路径设置后依然无法导入。请检查您的文件结构。")
        print(f"预期结构: a 'src/blocka2a/utils' 目录应存在于 '{project_root}' 中。")
        raise e


def generate_and_display_keys():
    """
    生成5套密钥对并以 JSON 格式完整打印。
    """
    print("=" * 70)
    print("PART 1: 批量生成密钥对")
    print("=" * 70)

    print("\n正在生成 5 套密钥 (Ed25519, BLS12-381, BN256)...")
    key_sets = crypto.generate_key_sets(count=5)
    print("密钥生成完毕。\n")

    for key_set in key_sets:
        print(f"--- KEY SET {key_set['set']} ---")

        # 使用 json.dumps 进行格式化输出，确保所有字段都完整显示
        # 我们需要一个自定义的转换器来处理 int 类型的大数
        def default_serializer(o):
            if isinstance(o, int):
                return str(o)  # 将大整数转换为字符串
            raise TypeError(f"Object of type {o.__class__.__name__} is not JSON serializable")

        print(json.dumps(key_set, indent=4, default=default_serializer))
        print("-" * 20)


def run_bn256_multisig_demo():
    """
    演示 BN256 库的多签名和聚合验证功能。
    """
    print("\n\n" + "=" * 70)
    print("PART 2: BN256 多签名验证试验")
    print("=" * 70)

    # --- 准备工作：生成3个参与方的密钥 ---
    print("\n[SETUP] 正在为 Alice, Bob, 和 Carol 生成 BN256 密钥对...")

    sk_alice, pk_alice = bls_bn256.generate_keypair()
    sk_bob, pk_bob = bls_bn256.generate_keypair()
    sk_carol, pk_carol = bls_bn256.generate_keypair()

    sks = [sk_alice, sk_bob, sk_carol]
    pks = [pk_alice, pk_bob, pk_carol]

    print("    密钥对生成完毕。")

    # --- 场景A: 多方签署【相同】消息 (高效验证) ---
    print("\n--- 场景 A: 验证多方对【相同】消息的签名 ---")
    msg_same = b"All parties agree to transfer 100 tokens to Dave."
    print(f"    共同消息: \"{msg_same.decode()}\"")

    # 1. 各方分别签名
    print("\n    1. Alice, Bob, Carol 分别对消息进行签名...")
    sigs_same = [bls_bn256.sign(msg_same, sk) for sk in sks]

    # 2. 聚合签名
    print("    2. 正在将 3 个签名聚合成 1 个...")
    sig_agg_same = bls_bn256.aggregate_sigs(sigs_same)

    # 3. 验证聚合签名 (肯定性测试)
    print("    3. 正在使用高效模式验证聚合签名...")
    is_valid_A = bls_bn256.verify_fast_aggregate_same_msg(pks, sig_agg_same, msg_same)
    print(f"       结果: {'✅ 验证通过' if is_valid_A else '❌ 验证失败'}")
    assert is_valid_A, "场景A的肯定性测试失败！"

    # 4. 验证聚合签名 (否定性测试 - 公钥列表不完整)
    print("\n    4. 正在进行否定性测试 (只用2个公钥去验证3个签名)...")
    is_invalid_A = bls_bn256.verify_fast_aggregate_same_msg(pks[:2], sig_agg_same, msg_same)
    print(f"       结果: {'✅ 正确地拒绝了签名' if not is_invalid_A else '❌ 未能拒绝签名'}")
    assert not is_invalid_A, "场景A的否定性测试失败！"

    # --- 场景B: 多方签署【不同】消息 ---
    print("\n--- 场景 B: 验证多方对【不同】消息的签名 ---")
    msgs_distinct = [
        b"Alice authorizes payment of 10 tokens.",
        b"Bob authorizes payment of 20 tokens.",
        b"Carol authorizes payment of 30 tokens."
    ]
    print("    Alice, Bob, Carol 分别签署了不同的交易消息。")

    # 1. 各方分别签名
    print("\n    1. 正在为各自的消息生成签名...")
    sigs_distinct = [bls_bn256.sign(m, sk) for m, sk in zip(msgs_distinct, sks)]

    # 2. 聚合签名
    print("    2. 正在聚合这些独立的签名...")
    sig_agg_distinct = bls_bn256.aggregate_sigs(sigs_distinct)

    # 3. 验证聚合签名 (肯定性测试)
    print("    3. 正在验证聚合签名...")
    is_valid_B = bls_bn256.verify_aggregate(pks, sig_agg_distinct, msgs_distinct)
    print(f"       结果: {'✅ 验证通过' if is_valid_B else '❌ 验证失败'}")
    assert is_valid_B, "场景B的肯定性测试失败！"

    # 4. 验证聚合签名 (否定性测试 - 消息被篡改)
    print("\n    4. 正在进行否定性测试 (篡改了其中一条消息)...")
    tampered_msgs = msgs_distinct.copy()
    tampered_msgs[1] = b"Bob authorizes payment of 999 tokens."  # Bob的消息被篡改
    is_invalid_B = bls_bn256.verify_aggregate(pks, sig_agg_distinct, tampered_msgs)
    print(f"       结果: {'✅ 正确地拒绝了签名' if not is_invalid_B else '❌ 未能拒绝签名'}")
    assert not is_invalid_B, "场景B的否定性测试失败！"

    print("\n" + "=" * 70)
    print("所有 BN256 多签试验均已成功完成！")
    print("=" * 70)


if __name__ == "__main__":
    generate_and_display_keys()
    run_bn256_multisig_demo()