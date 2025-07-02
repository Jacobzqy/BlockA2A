import sys
import os
import hashlib
import json
from datetime import datetime, timedelta, timezone
import time
from eth_abi.packed import encode_packed
import base58
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.blocka2a.clients.blocka2a_client import BlockA2AClient
from src.blocka2a.clients.task_initiator import TaskInitiator
from src.blocka2a.clients.signature_aggregator import SignatureAggregator
from src.blocka2a.utils import crypto, bn256
from src.blocka2a.types import PublicKeyEntry, ServiceEntry, Capabilities, PolicyConstraints, Proof
from src.blocka2a.clients.service_server import ServiceServer

from src.blocka2a.types import PublicKeyEntry, ServiceEntry, Capabilities, PolicyConstraints, Proof, DIDDocument, \
    BLSPubkey, BLSSignature, BLSPrivateKey, Ed25519PrivateKey, Ed25519Signature, Ed25519PublicKey, AccessToken

def create_payload(data_hash: bytes, milestone: str) -> bytes:
    """
    构造与合约 abi.encodePacked 完全一致的字节串。
    """
    return encode_packed(
        ["bytes32", "string", "string"],
        [data_hash, "|", milestone]
    )

def main():
    
    # Hardhat 本地节点的默认 RPC 地址
    rpc_endpoint = "http://127.0.0.1:8545/"

    # 本地部署的 AgentGovernanceContract (AGC) 地址
    agc_address = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
    dac_address = "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"
    ilc_address = "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"
    acc_address = "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"

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
    # 2. 生成两个 agent 的密钥对
    # ==========================================================================
    print("\n🚀 步骤 2: 生成密钥对...")
    try:
        keys = crypto.generate_key_sets(count=2)  # 生成两组密钥
        ed_key_info1, bls_key_info1 = keys[0]["ed25519"], keys[0]["bn256_g2"]
        ed_key_info2, bls_key_info2 = keys[1]["ed25519"], keys[1]["bn256_g2"]
        print(f"✅ Agent 1 密钥生成成功: Ed25519 公钥: {ed_key_info1['public_key_multibase'][:20]}...")
        print(f"✅ Agent 1 BLS 公钥: {bls_key_info1['public_key_multibase'][:20]}...")
        print(f"✅ Agent 2 密钥生成成功: Ed25519 公钥: {ed_key_info2['public_key_multibase'][:20]}...")
        print(f"✅ Agent 2 BLS 公钥: {bls_key_info2['public_key_multibase'][:20]}...")
    except Exception as e:
        print(f"❌ 密钥生成失败: {e}")
        raise

    # ==========================================================================
    # 3. 构建两个 DID 文档
    # ==========================================================================
    print("\n🚀 步骤 3: 构建 DID 文档...")
    try:
        did1 = BlockA2AClient.generate_did([
            ed_key_info1["public_key_multibase"],
            bls_key_info1["public_key_multibase"]
        ])
        did2 = BlockA2AClient.generate_did([
            ed_key_info2["public_key_multibase"],
            bls_key_info2["public_key_multibase"]
        ])
        public_keys1 = [
            PublicKeyEntry(
                id=f"{did1}#keys-1",
                type="Ed25519VerificationKey2020",
                publicKeyMultibase=ed_key_info1["public_key_multibase"]
            ),
            PublicKeyEntry(
                id=f"{did1}#keys-2",
                type="Bls256G2Key2020",
                publicKeyMultibase=bls_key_info1["public_key_multibase"]
            )
        ]
        public_keys2 = [
            PublicKeyEntry(
                id=f"{did2}#keys-1",
                type="Ed25519VerificationKey2020",
                publicKeyMultibase=ed_key_info2["public_key_multibase"]
            ),
            PublicKeyEntry(
                id=f"{did2}#keys-2",
                type="Bls256G2Key2020",
                publicKeyMultibase=bls_key_info2["public_key_multibase"]
            )
        ]
        services = [
            ServiceEntry(
                id=f"{did1}#resource-1",
                type="AgentCommunicationEndpoint",
                serviceEndpoint="https://agent-a.example.com/api"
            ),
            ServiceEntry(
                id=f"{did1}#resource-2",
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
        print(f"✅ DID 文档构建成功: DID1 = {did1}, DID2 = {did2}")
    except Exception as e:
        print(f"❌ DID 文档构建失败: {e}")
        raise

    # ==========================================================================
    # 4. 注册两个 DID
    # ==========================================================================
    print("\n🚀 步骤 4: 注册 DID...")
    try:
        tx_hash1, cid1 = client.register_did(
            did=did1,
            public_keys=public_keys1,
            services=services,
            capabilities=capabilities,
            policy_constraints=policy_constraints,
            proof=None,
            required_sigs_for_update=1
        )
        tx_hash2, cid2 = client.register_did(
            did=did2,
            public_keys=public_keys2,
            services=services,
            capabilities=capabilities,
            policy_constraints=policy_constraints,
            proof=None,
            required_sigs_for_update=1
        )
        print(f"✅ DID 注册成功: DID1 tx_hash={tx_hash1.hex()[:20]}..., cid={cid1}")
        print(f"✅ DID 注册成功: DID2 tx_hash={tx_hash2.hex()[:20]}..., cid={cid2}")
    except Exception as e:
        print(f"❌ DID 注册失败: {e}")
        raise

    # ==========================================================================
    # 5. 验证两个 DID
    # ==========================================================================
    print("\n🚖 步骤 5: 验证 DID...")
    print("\n Skip DID verification step for now")
    # try:
    #     valid1 = client.verify(did=did1, proof=None)
    #     valid2 = client.verify(did=did2, proof=None)
    #     print(f"✅ DID1 验证通过: {valid1}")
    #     print(f"✅ DID2 验证通过: {valid2}")
    # except Exception as e:
    #     print(f"❌ DID 验证失败: {e}")
    #     raise

    # ==========================================================================
    # 6. 生成两个任务签名
    # ==========================================================================
    print("\n🚀 步骤 6: 生成任务签名...")
    try:
        task_metadata = {"task_id": "task-123", "description": "Sample task"}
        task_json = json.dumps(task_metadata, separators=(",", ":"), sort_keys=True)
        task_hash = hashlib.sha256(task_json.encode()).digest()
        milestone = "milestone-1"

        # print(f"DEBUG: bls_key_info1: {bls_key_info1}")
        # print(f"DEBUG: bls_key_info2: {bls_key_info2}")

        bls_private_key1 = bls_key_info1["private_key_int"]
        bls_private_key2 = bls_key_info2["private_key_int"]
        ed_private_key1 = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(ed_key_info1["private_key_hex"]))
        ed_private_key2 = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(ed_key_info2["private_key_hex"]))
        # print(f"DEBUG: bls_private_key1 type: {type(bls_private_key1)}")
        # print(f"DEBUG: bls_private_key2 type: {type(bls_private_key2)}")

        if isinstance(bls_private_key1, str):
            bls_private_key1 = int(bls_private_key1, 16)
        if isinstance(bls_private_key2, str):
            bls_private_key2 = int(bls_private_key2, 16)
        if not isinstance(bls_private_key1, int):
            raise TypeError(f"BLS private key 1 must be int, got {type(bls_private_key1)}")
        if not isinstance(bls_private_key2, int):
            raise TypeError(f"BLS private key 2 must be int, got {type(bls_private_key2)}")

        signature1 = BlockA2AClient.sign_task(
            private_key=ed_private_key1,
            task_hash=task_hash,
            milestone=milestone,
            proof_type="Ed25519Signature2020"
        )
        signature2 = BlockA2AClient.sign_task(
            private_key=ed_private_key2,
            task_hash=task_hash,
            milestone=milestone,
            proof_type="Ed25519Signature2020"
        )
        print(f"✅ 任务签名生成成功: signature1={signature1.hex()[:20]}...")
        print(f"✅ 任务签名生成成功: signature2={signature2.hex()[:20]}...")
    except Exception as e:
        print(f"❌ 任务签名生成失败: {e}")
        raise
    
    start = time.time()
    message = task_hash.hex() + "|" + milestone  # 必须与签名时相同
    # proof = Proof(
    #     type="BLS256Signature2020",
    #     created=datetime.now(timezone.utc).isoformat(),  # ISO 8601格式
    #     verificationMethod=did1 + "#keys-2",  # 必须是DID文档中存在的公钥ID
    #     proofValue=base58.b58encode(signature1)
    # )
    proof = Proof(
        type="Ed25519Signature2020",
        created=datetime.now(timezone.utc).isoformat(),  # ISO 8601格式
        verificationMethod=did1 + "#keys-1",  # 必须是DID文档中存在的公钥ID
        proofValue=signature1.hex()
    )
    is_valid = client.verify(did1, proof=proof, message=message.encode('utf-8'))
    end = time.time()
    print(f"Signature Verification: {end - start:.6f} 秒")
    print(f"✅ 签名验证结果: {is_valid}")

    # ==========================================================================
    # 7. 发起任务
    # ==========================================================================
    print("\n🚀 步骤 7: 发起任务...")
    try:
        task_initiator = TaskInitiator(
            rpc_endpoint=rpc_endpoint,
            initiator_did=did1,
            data_anchoring_address=dac_address,
            private_key=private_key,
            ipfs_gateway=ipfs_gateway,
            default_gas=default_gas
        )

        participants = [did1, did2]  # 两个 agent
        description = "Sample task for testing TaskInitiator with two agents"
        deadline = int((datetime.now() + timedelta(days=7)).timestamp())

        cid, tx_hash, data_hash = task_initiator.initiate_task(
            participants=participants,
            description=description,
            deadline=deadline
        )
        print(f"✅ 任务发起成功: cid={cid}, tx_hash={tx_hash.hex()[:20]}...")
    except Exception as e:
        print(f"❌ 任务发起失败: {e}")
        raise

    # ==========================================================================
    # 8. 聚合签名并提交任务验证 
    # ==========================================================================
    print("\n🚀 步骤 8: 聚合签名并提交任务验证...")
    payload = create_payload(data_hash, milestone)
    try:
        task_validation_start = time.time()
        aggregator = SignatureAggregator(
            rpc_endpoint=rpc_endpoint,
            data_anchoring_address=dac_address,
            private_key=private_key,
            ipfs_gateway=ipfs_gateway,
            default_gas=default_gas
        )

        signature3 = bn256.sign(
            payload,
            2833825224628770647255613288651483959178104459000430758204801703807178990217,
            b"DAC"
        )
        signature4 = bn256.sign(
            payload,
            19020176885312313733264572853669371179783749614111895563810414749642828590597,
            b"DAC"
        )
        #signature3 = bn256.deserialize_g1(signature3)
        #signature4 = bn256.deserialize_g1(signature4)
        signatures = [signature3, signature4]
        dids = [did1, did2]
        pks_mask = 0x03  # 选择 _blsPubKeyList[0] 和 _blsPubKeyList[1]

        agg_sig = bn256.aggregate_sigs(signatures)
        task_validation_end = time.time()
        tx_hash = aggregator.submit_task_validation(
            agg_sig=[agg_sig[0].n, agg_sig[1].n],
            data_hash=data_hash,
            milestone=milestone,
            dids=dids,
            pks_mask=pks_mask
        )
        
        print(f"Aggregated signature completed in {(task_validation_end - task_validation_start):.6f} s")
        print(f"✅ 任务验证提交成功: tx_hash={tx_hash.hex()[:20]}...")
    except Exception as e:
        print(f"❌ 任务验证提交失败: {e}")
        raise

    # ==========================================================================
    # 9. 测量资源请求和令牌验证时间
    # ==========================================================================
    print("\n⏱️ 步骤 9: 测量资源请求和令牌验证时间...")
    try:
        # 初始化服务服务器
        server = ServiceServer(
            rpc_endpoint=rpc_endpoint,
            acc_address=acc_address,
            private_key=private_key,
            resource_identifier="resource1",
            default_gas=default_gas
        )
        
        # 注册一个动作
        server.register_action("action1")
        
        # 测量 request_resource 时间
        start_request = time.time()
        token = client.request_resource(
            did=did1,
            resource_identifier="resource1",
            action_identifier="action1"
        )
        end_request = time.time()
        request_time = end_request - start_request
        
        # 测量 verify_token 时间
        start_verify = time.time()
        is_valid = server.verify_token(token)
        end_verify = time.time()
        verify_time = end_verify - start_verify
        
        print(f"✅ Token issuance: {request_time:.6f} 秒")
        print(f"✅ token verification: {verify_time:.6f} 秒")
        print(f"✅ 验证结果: {'有效' if is_valid else '无效'}")
    except Exception as e:
        print(f"❌ 测量失败: {e}")
        raise

    

if __name__ == "__main__":
    main()