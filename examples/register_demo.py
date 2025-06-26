import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.blocka2a.clients.blocka2a_client import BlockA2AClient
from src.blocka2a.utils import crypto
from src.blocka2a.types import PublicKeyEntry, ServiceEntry, Capabilities, PolicyConstraints, DIDDocument


def main():
    # ==========================================================================
    # 1. 初始化 BlockA2A 客户端
    # ==========================================================================
    print("🚀 步骤 1: 初始化客户端...")

    # Hardhat 本地节点的默认 RPC 地址
    rpc_endpoint = "http://127.0.0.1:8545/"

    # 本地部署的 AgentGovernanceContract (AGC) 地址
    agc_address = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"

    # 暂时先忽略其他合约，使用占位符。
    acc_address = "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"
    ilc_address = "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"
    dac_address = "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"

    # Hardhat 节点提供的第一个测试账户的私钥
    private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

    # 本地 IPFS 节点 API 地址
    ipfs_gateway = "/ip4/127.0.0.1/tcp/5001/http"

    try:
        client = BlockA2AClient(
            rpc_endpoint=rpc_endpoint,
            acc_address=acc_address,
            ilc_address=ilc_address,
            agc_address=agc_address,
            dac_address=dac_address,
            private_key=private_key,
            ipfs_gateway=ipfs_gateway
        )
        print("✅ BlockA2AClient 实例初始化成功！")
        print(f"   - Signer Address: {client._acct.address}")
        print(f"   - IPFS Gateway: {ipfs_gateway}")
    except Exception as e:
        print(f"❌ 初始化失败: {e}")
        return

    # ==========================================================================
    # 2. 生成密钥并创建 DID
    # ==========================================================================
    print("\n🚀 步骤 2: 生成密钥并创建 DID...")

    # 调用 crypto 工具生成一套 Ed25519 和 BLS 密钥
    keys = crypto.generate_key_sets(count=1)[0]
    ed_key_info = keys["ed25519"]
    bls_key_info = keys["bls12_381_g2"]

    print(f"   - 已生成 Ed25519 公钥: {ed_key_info['public_key_multibase'][:20]}...")
    print(f"   - 已生成 BLS G2 公钥: {bls_key_info['public_key_multibase'][:20]}...")

    # 提取 multibase 格式的公钥用于生成 DID
    public_keys_multibase = [
        ed_key_info["public_key_multibase"],
        bls_key_info["public_key_multibase"]
    ]

    # 使用客户端的类方法生成 DID
    did = BlockA2AClient.generate_did(public_keys_multibase)
    print(f"✅ DID 生成成功: {did}")

    # ==========================================================================
    # 3. 准备注册 DID 所需的参数
    # ==========================================================================
    print("\n🚀 步骤 3: 准备 DID Document 的所有参数...")

    # a. 创建公钥条目 (PublicKeyEntry)
    public_keys_for_doc = [
        PublicKeyEntry(
            id=f"{did}#keys-1",
            type="Ed25519VerificationKey2020",
            publicKeyMultibase=ed_key_info["public_key_multibase"]
        ),
        PublicKeyEntry(
            id=f"{did}#keys-2",
            type="Bls12381G1Key2020",
            publicKeyMultibase=bls_key_info["public_key_multibase"]
        )
    ]

    # b. 创建服务条目 (ServiceEntry)
    services_for_doc = [
        ServiceEntry(
            id=f"{did}#resource-1",
            type="AgentCommunicationEndpoint",
            serviceEndpoint=f"https://agent-a.example.com/api"
        ),
        ServiceEntry(
            id=f"{did}#resource-2",
            type="DocumentEndpoint",
            serviceEndpoint=f"https://agent-b.example.com/api"
        )
    ]

    # c. 填充 Capabilities
    capabilities_for_doc = Capabilities(
        supportedModels=["gpt-4", "llama3"],
        maxComputeTime="5s",
        permissions=["read", "write"]
    )

    # d. 填充 PolicyConstraints
    policy_constraints_for_doc = PolicyConstraints(
        allowed_interaction_hours="09:00-18:00 UTC",
        max_data_size="10MB"
    )

    # e. 设置签名要求
    required_sigs = 1

    print("✅ 所有参数准备就绪。")

    # ==========================================================================
    # 3.5. 预览将要注册的 DID Document (已更新)
    # ==========================================================================
    print("\n🚀 步骤 3.5: 预览将要注册的 DID Document...")

    # 将所有组件组装成一个 DIDDocument 对象
    # 注意：现在重新包含了 "capabilities" 字段
    document_to_register = DIDDocument(
        id=did,
        publicKey=public_keys_for_doc,
        service=services_for_doc,
        capabilities=capabilities_for_doc,
        policy_constraints=policy_constraints_for_doc,
        proof=None
    )

    # 以美观的 JSON 格式打印文档
    print("-------------------- DID Document (Preview) --------------------")
    print(document_to_register.to_json(indent=2))
    print("----------------------------------------------------------------")

    # ==========================================================================
    # 4. 执行注册
    # ==========================================================================
    print("\n🚀 步骤 4: 发送交易，注册 DID...")

    try:
        tx_hash, cid = client.register_did(
            did=did,
            public_keys=public_keys_for_doc,
            services=services_for_doc,
            capabilities=capabilities_for_doc,
            policy_constraints=policy_constraints_for_doc,
            proof=None,  # 首次注册，proof 可以为 None
            required_sigs_for_update=required_sigs
        )
        print("\n🎉🎉🎉 DID 注册成功！🎉🎉🎉")
        print(f"   - 链上交易哈希 (Tx Hash): {tx_hash.hex()}")
        print(f"   - IPFS CID (DID Document 地址): {cid}")
        print("\n👉 你现在可以使用 IPFS cat 命令或浏览器网关查看这个 CID 的内容:")
        print(f"   ipfs cat {cid}")
        print(f"   http://127.0.0.1:8080/ipfs/{cid}")

    except Exception as e:
        print(f"\n❌ DID 注册失败: {e}")


if __name__ == "__main__":
    main()