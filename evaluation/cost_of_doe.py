import sys
import os
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import List, Optional
import time
import base58
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.blocka2a.clients.blocka2a_client import BlockA2AClient
from src.blocka2a.clients.task_initiator import TaskInitiator
from src.blocka2a.clients.signature_aggregator import SignatureAggregator
from src.blocka2a.utils import crypto
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
    agc_address = "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"
    acc_address = "0xa513E6E4b8f2a923D98304ec87F64353C4D5C853"
    ilc_address = "0x0165878A594ca255338adfa4d48449f69242Eb8F"
    dac_address = "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"

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
    # 5. 测量 AGC 函数执行时间
    # ==========================================================================
    print("\n⏱️ 步骤 5: 测量 AGC 函数执行时间...")
    try:
        # 获取当前 DID 信息
        current_document_hash, current_cid = client._agc.functions.resolve(did1).call()
        print(f"✅ 当前 DID 状态: docHash={current_document_hash.hex()}, cid={current_cid}")
        
        # 准备新文档哈希
        new_document_content = b"Updated DID document content"
        new_document_hash = hashlib.sha256(new_document_content).digest()
        print(f"✅ 新文档哈希: {new_document_hash.hex()}")
        
        # 准备签名数据 (简化版，实际需要有效的 BLS 签名)
        # 注意: 实际应用中需要生成有效的聚合签名，这里使用测试签名
        agg_sig = [12345678, 87654321]  # 简化的签名格式
        pks_mask = 0b00000001  # 使用第一个公钥
        
        # 1. 测量 resolve 时间
        start_resolve = time.time()
        doc_hash, cid = client._agc.functions.resolve(did1).call()
        resolve_time = time.time() - start_resolve
        print(f"✅ resolve 执行时间: {resolve_time:.6f} 秒")
        print(f"  返回结果: docHash={doc_hash.hex()}, cid={cid}")
        
        # 2. 测量 update 时间
        # 封装 update 函数以便测量
        def execute_update():
            tx = client._agc.functions.update(
                did1,
                new_document_hash,
                agg_sig,
                pks_mask
            ).build_transaction({
                'from': client._account.address,
                'gas': client._default_gas,
                'nonce': client._web3.eth.get_transaction_count(client._account.address),
            })
            signed_tx = client._account.sign_transaction(tx)
            tx_hash = client._web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            return tx_hash
        
        # 发送交易并测量时间
        start_update = time.time()
        tx_hash = execute_update()
        update_send_time = time.time() - start_update
        print(f"✅ update 交易发送时间: {update_send_time:.6f} 秒")
        print(f"  交易哈希: {tx_hash.hex()}")
        
        # 等待交易确认
        start_confirm = time.time()
        receipt = client._web3.eth.wait_for_transaction_receipt(tx_hash)
        confirm_time = time.time() - start_confirm
        print(f"✅ update 交易确认时间: {confirm_time:.6f} 秒")
        print(f"  区块号: {receipt.blockNumber}, Gas 消耗: {receipt.gasUsed}")
        
        # 3. 测量 revoke 时间
        # 封装 revoke 函数以便测量
        def execute_revoke():
            tx = client._agc.functions.revoke(
                did1,
                agg_sig,
                pks_mask
            ).build_transaction({
                'from': client._account.address,
                'gas': client._default_gas,
                'nonce': client._web3.eth.get_transaction_count(client._account.address),
            })
            signed_tx = client._account.sign_transaction(tx)
            return client._web3.eth.send_raw_transaction(signed_tx.rawTransaction)
        
        # 发送交易并测量时间
        start_revoke = time.time()
        tx_hash = execute_revoke()
        revoke_send_time = time.time() - start_revoke
        print(f"✅ revoke 交易发送时间: {revoke_send_time:.6f} 秒")
        print(f"  交易哈希: {tx_hash.hex()}")
        
        # 等待交易确认
        start_confirm = time.time()
        receipt = client._web3.eth.wait_for_transaction_receipt(tx_hash)
        confirm_time = time.time() - start_confirm
        print(f"✅ revoke 交易确认时间: {confirm_time:.6f} 秒")
        print(f"  区块号: {receipt.blockNumber}, Gas 消耗: {receipt.gasUsed}")
        
        # 4. 验证 revoke 后的状态
        start_resolve = time.time()
        try:
            # 尝试解析已撤销的 DID
            doc_hash, cid = client._agc.functions.resolve(did1).call()
            print("⚠️ 预期错误但未抛出: DID 应已被撤销")
        except Exception as e:
            resolve_time = time.time() - start_resolve
            print(f"✅ 解析已撤销 DID 时间: {resolve_time:.6f} 秒")
            print(f"  预期错误: {str(e)}")
        
        print("\n📊 AGC 函数性能总结:")
        print(f"  resolve() 调用时间: {resolve_time:.6f} 秒")
        print(f"  update() 总时间: {update_send_time + confirm_time:.6f} 秒 (发送: {update_send_time:.6f}, 确认: {confirm_time:.6f})")
        print(f"  revoke() 总时间: {revoke_send_time + confirm_time:.6f} 秒 (发送: {revoke_send_time:.6f}, 确认: {confirm_time:.6f})")
        
    except Exception as e:
        print(f"❌ AGC 函数测试失败: {e}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == "__main__":
    main()
