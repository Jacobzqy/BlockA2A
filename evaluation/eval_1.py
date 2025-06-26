import sys
import os
import hashlib
import json
from datetime import datetime, timedelta
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.blocka2a.clients.blocka2a_client import BlockA2AClient
from src.blocka2a.clients.task_initiator import TaskInitiator
from src.blocka2a.utils import crypto
from src.blocka2a.types import PublicKeyEntry, ServiceEntry, Capabilities, PolicyConstraints, DIDDocument, Proof
from src.blocka2a.clients.signature_aggregator import SignatureAggregator
def main():

    # Hardhat 本地节点的默认 RPC 地址
    rpc_endpoint = "http://127.0.0.1:8545/"

    # 本地部署的 AgentGovernanceContract (AGC) 地址
    agc_address = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
    acc_address = "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"
    ilc_address = "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"
    dac_address = "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"

    # Hardhat 节点提供的第一个测试账户的私钥
    private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    ipfs_gateway = "/ip4/127.0.0.1/tcp/5001/http"
    default_gas = 2_000_000

    # ==========================================================================
    # 1. 初始化客户端
    # ==========================================================================
    print("\n🚀 步骤 1: 初始化客户端...")
    try:
        client = BlockA2AClient(
            rpc_endpoint=rpc_endpoint,
            acc_address=acc_address,
            ilc_address=ilc_address,
            agc_address=agc_address,
            dac_address=dac_address,
            private_key=private_key,
            ipfs_gateway=ipfs_gateway,
            default_gas=default_gas
        )
        print("✅ 客户端初始化成功")
    except Exception as e:
        print(f"❌ 客户端初始化失败: {e}")
        raise

    # ==========================================================================
    # 2. 生成密钥对
    # ==========================================================================
    print("\n🚀 步骤 2: 生成密钥对...")
    try:
        keys = crypto.generate_key_sets(count=1)[0]
        ed_key_info = keys["ed25519"]
        bls_key_info = keys["bls12_381_g2"]
        print(f"✅ 密钥生成成功: Ed25519 公钥: {ed_key_info['public_key_multibase'][:20]}...")
        print(f"✅ BLS 公钥: {bls_key_info['public_key_multibase'][:20]}...")
    except Exception as e:
        print(f"❌ 密钥生成失败: {e}")
        raise

    # ==========================================================================
    # 3. 构建 DID 文档
    # ==========================================================================
    print("\n🚀 步骤 3: 构建 DID 文档...")
    try:
        did = BlockA2AClient.generate_did([
            ed_key_info["public_key_multibase"],
            bls_key_info["public_key_multibase"]
        ])
        public_keys = [
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
        services = [
            ServiceEntry(
                id=f"{did}#resource-1",
                type="AgentCommunicationEndpoint",
                serviceEndpoint="https://agent-a.example.com/api"
            ),
            ServiceEntry(
                id=f"{did}#resource-2",
                type="DocumentEndpoint",
                serviceEndpoint="https://agent-b.example.com/api"
            )
        ]
        capabilities = Capabilities(
            maxComputeTime="5s",
            permissions=["read", "write"],
            supportedModels=["gpt-4", "llama3"]
        )
        policy_constraints = PolicyConstraints(
            allowed_interaction_hours="09:00-18:00 UTC",
            max_data_size="10MB"
        )
        print(f"✅ DID 文档构建成功: DID = {did}")
    except Exception as e:
        print(f"❌ DID 文档构建失败: {e}")
        raise

    # ==========================================================================
    # 4. 注册 DID
    # ==========================================================================
    print("\n🚀 步骤 4: 注册 DID...")
    try:
        tx_hash, cid = client.register_did(
            did=did,
            public_keys=public_keys,
            services=services,
            capabilities=capabilities,
            policy_constraints=policy_constraints,
            proof=None,
            required_sigs_for_update=1
        )
        print(f"✅ DID 注册成功: tx_hash={tx_hash.hex()[:20]}..., cid={cid}")
    except Exception as e:
        print(f"❌ DID 注册失败: {e}")
        raise

    # ==========================================================================
    # 5. 验证 DID
    # ==========================================================================
    print("\n🚖 步骤 5: 验证 DID...")
    try:
        valid = client.verify(did=did, proof=None)
        print(f"✅ DID 验证通过: {valid}")
    except Exception as e:
        print(f"❌ DID 验证失败: {e}")
        raise

    # ==========================================================================
    # 6. 生成任务签名
    # ==========================================================================
    print("\n🚀 步骤 6: 生成任务签名...")
    try:
        task_metadata = {"task_id": "task-123", "description": "Sample task"}
        task_json = json.dumps(task_metadata, separators=(",", ":"), sort_keys=True)
        task_hash = hashlib.sha256(task_json.encode()).digest()
        milestone = "milestone-1"

        bls_private_key = bls_key_info["private_key_int"]

        if isinstance(bls_private_key, str):
            bls_private_key = int(bls_private_key, 16)
        if not isinstance(bls_private_key, int):
            raise TypeError(f"BLS private key must be int, got {type(bls_private_key)}")

        signature = BlockA2AClient.sign_task(
            bls_sk=bls_private_key,
            task_hash=task_hash,
            milestone=milestone
        )
        print(f"✅ 任务签名生成成功: {signature.hex()[:20]}...")
    except Exception as e:
        print(f"❌ 任务签名生成失败: {e}")
        raise

    # ==========================================================================
    # 7. 发起任务
    # ==========================================================================
    print("\n🚀 步骤 7: 发起任务...")
    try:
        # 初始化 TaskInitiator
        task_initiator = TaskInitiator(
            rpc_endpoint=rpc_endpoint,
            initiator_did=did,
            data_anchoring_address=dac_address,
            private_key=private_key,
            ipfs_gateway=ipfs_gateway,
            default_gas=default_gas
        )

        # 设置任务参数
        participants = [did]  # 示例：当前 DID 作为唯一参与者
        description = "Sample task for testing TaskInitiator"
        deadline = int((datetime.now() + timedelta(days=7)).timestamp())  # 7 天后

        # 发起任务
        cid, tx_hash = task_initiator.initiate_task(
            participants=participants,
            description=description,
            deadline=deadline
        )
        print(f"✅ 任务发起成功: cid={cid}, tx_hash={tx_hash.hex()[:20]}...")
    except Exception as e:
        print(f"❌ 任务发起失败: {e}")
        raise

    # ==========================================================================
    # 8. 聚合签名并提交任务验证   TODO: 验证部分存在bug
    # ==========================================================================
    print("\n🚀 步骤 8: 聚合签名并提交任务验证...")
    try:
        task_validation_start = time.time()
        aggregator = SignatureAggregator(
            rpc_endpoint=rpc_endpoint,
            data_anchoring_address=dac_address,
            private_key=private_key,
            ipfs_gateway=ipfs_gateway,
            default_gas=default_gas
        )

        signatures = [signature]
        dids = [did]
        pks_mask = 0x01  # 选择 _blsPubKeyList[0]

        agg_sig = aggregator.aggregate(signatures)

        tx_hash = aggregator.submit_task_validation(
            agg_sig=agg_sig,
            data_hash=task_hash,
            milestone=milestone,
            dids=dids,
            pks_mask=pks_mask
        )
        task_validation_end = time.time()
        print(f"Task validation completed in {(task_validation_end - task_validation_start):.2f} s")
        print(f"✅ 任务验证提交成功: tx_hash={tx_hash.hex()[:20]}...")
    except Exception as e:
        print(f"❌ 任务验证提交失败: {e}")
        raise

if __name__ == "__main__":
    main()