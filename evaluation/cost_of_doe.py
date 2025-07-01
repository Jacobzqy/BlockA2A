import sys
import os
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import List, Optional
import time
import base58
from zoneinfo import ZoneInfo
from eth_abi.packed import encode_packed
from py_ecc.bls import G2ProofOfPossession as BLS  # 假设使用 py_ecc 作为 BLS 库
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.blocka2a.clients.blocka2a_client import BlockA2AClient
from src.blocka2a.clients.task_initiator import TaskInitiator
from src.blocka2a.clients.signature_aggregator import SignatureAggregator
from src.blocka2a.utils import crypto, bn256
from src.blocka2a.types import PublicKeyEntry, ServiceEntry, Capabilities, PolicyConstraints, Proof
from src.blocka2a.clients.service_server import ServiceServer
def measure_execution_time(func, *args, **kwargs):
    """测量函数执行时间"""
    start_time = time.time()
    result = func(*args, **kwargs)
    end_time = time.time()
    return result, end_time - start_time


def main():
    # Hardhat 本地节点的默认 RPC 地址
    rpc_endpoint = "http://127.0.0.1:8545/"

    # 本地部署的 AgentGovernanceContract (AGC) 地址
    agc_address = "0x1613beB3B2C4f22Ee086B2b38C1476A3cE7f78E8"
    acc_address = "0x95401dc811bb5740090279Ba06cfA8fcF6113778"
    ilc_address = "0xf5059a5D33d5853360D16C683c16e67980206f36"
    dac_address = "0x851356ae760d987E095750cCeb3bC6014560891C"

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
        ed_key_info1, bls_key_info1 = keys[0]["ed25519"], keys[0]["bls12_381_g2"]
        ed_key_info2, bls_key_info2 = keys[1]["ed25519"], keys[1]["bls12_381_g2"]
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
                type="Bls12381G1Key2020",
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
                type="Bls12381G1Key2020",
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
    # 5. 测量 Evidence Collection 的时间
    # ==========================================================================
    retrieved_data = []
    
    task = {
        "task_id": f"task-{int(time.time())}",
        "description": "Collect evidence for agent behavior",
    }

    # expiry = int((datetime.now(ZoneInfo("UTC")) + timedelta(days=10)).timestamp())
    expiry = client._w3.eth.get_block("latest")["timestamp"] + 3600
    tx_hash, cid, data_hash = client.anchor_data(task, expiry=expiry)

    start = time.time()
    for i in range(5):
        try:
            data_hash_ret, cid_ret, expiry_ret, status_ret = client.get_on_chain_data(data_hash)
            retrieved_data.append({
                "source": "on_chain",
                "data_hash": data_hash_ret.hex(),
                "cid": cid_ret,
                "expiry": expiry_ret,
                "status": status_ret,
                "retrieval_index": i + 1
            })
            print(f"On-chain retrieval {i + 1}: data_hash={data_hash_ret.hex()}, cid={cid_ret}")
        except Exception as e:
            print(f"On-chain retrieval {i + 1} failed: {e}")
            continue

    # 链下获取 10 次
    for i in range(10):
        try:
            off_chain_data = client.get_off_chain_data(cid)
            retrieved_data.append({
                "source": "off_chain",
                "data": off_chain_data,
                "retrieval_index": i + 1
            })
            print(f"Off-chain retrieval {i + 1}: data={off_chain_data}")
        except Exception as e:
            print(f"Off-chain retrieval {i + 1} failed: {e}")
            continue

    # 将所有获取的数据存储到链下（IPFS）
    print("\nStoring retrieved data to IPFS...")
    try:
        retrieved_json = json.dumps(retrieved_data, separators=(",", ":"), sorted_keys=True)
        retrieved_cid = client._ipfs.add_json(retrieved_json)
        print(f"All retrieved data stored to IPFS with CID: {retrieved_cid}")
    except Exception as e:
        print(f"Failed to store retrieved data to IPFS: {e}")

    end = time.time()
    elapsed_time = end - start
    print(f"\nEvidence Collection completed in {elapsed_time:.6f} s")
    


if __name__ == "__main__":
    main()
