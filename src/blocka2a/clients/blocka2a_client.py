import hashlib
import time
import base58
import json
import multibase

# from Crypto.SelfTest.Protocol.test_ecdh import public_key

from py_ecc.bls.g2_primitives import pubkey_to_G1
from web3 import Web3
from web3.types import HexBytes
from src.blocka2a.utils import crypto, bn256
from typing import Optional, List, Any, Tuple, Union
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from py_ecc.bls import G2ProofOfPossession

from src.blocka2a.clients.base_client import BaseClient
from src.blocka2a.clients.errors import InvalidParameterError, IdentityError, ContractError, NetworkError, LedgerError
from src.blocka2a.types import PublicKeyEntry, ServiceEntry, Capabilities, PolicyConstraints, Proof, DIDDocument, \
    BLSPubkey, BLSSignature, BLSPrivateKey, AccessToken
from src.blocka2a.contracts import access_control_contract, interaction_logic_contract, agent_governance_contract, data_anchoring_contract


class BlockA2AClient(BaseClient):
    """BlockA2A SDK client that handles DID operations, data anchoring, and task signatures."""

    def __init__(
        self,
        rpc_endpoint: str,
        acc_address: str,
        ilc_address: str,
        agc_address: str,
        dac_address: str,
        private_key: Optional[str] = None,
        ipfs_gateway: Optional[str] = None,
        default_gas: int = 2_000_000,
    ) -> None:
        """
        Initialize a BlockA2AClient.

        Args:
            rpc_endpoint: URL of the Ethereum JSON-RPC endpoint.
            acc_address: Address of the AccessControlContract.
            ilc_address: Address of the InteractionLogicContract.
            agc_address: Address of the AgentGovernanceContract.
            dac_address: Address of the DataAnchoringContract.
            private_key: Hex string of the EOA private key for signing transactions.
                         If None, write operations are disabled.
            ipfs_gateway: URL or multi-addr of the IPFS API endpoint; if None, off-chain ops disabled.
            default_gas: Default gas limit for transactions (in Wei).

        Raises:
            InvalidParameterError: If any contract address is not a valid Ethereum address.
        """
        super().__init__(
            rpc_endpoint=rpc_endpoint,
            private_key=private_key,
            ipfs_gateway=ipfs_gateway,
            default_gas=default_gas,
        )

        # Load each contract via BaseClient._load_contract()
        self._acc = self._load_contract(access_control_contract.get_contract, acc_address)
        self._ilc = self._load_contract(interaction_logic_contract.get_contract, ilc_address)
        self._agc = self._load_contract(agent_governance_contract.get_contract, agc_address)
        self._dac = self._load_contract(data_anchoring_contract.get_contract, dac_address)

    @classmethod
    def _verify_proof(cls, document: DIDDocument, proof: Optional[Proof], public_keys: List[PublicKeyEntry]) -> None:
        """
        Verify the Ed25519 proof in a DIDDocument; skip if proof is None.

        Args:
            document: The DIDDocument to verify.
            proof: Optional Proof object from the document.
            public_keys: List of PublicKeyEntry in the document.

        Raises:
            InvalidParameterError: If proof type is unsupported or key format invalid.
            IdentityError: If proof verification fails.
        """
        if proof is None:
            return

        if proof.type != "Ed25519Signature2020":
            raise InvalidParameterError(f"Unsupported proof type: {proof.type}")

        pk_entry = next((pk for pk in public_keys if pk.id == proof.verificationMethod), None)

        if pk_entry is None:
            raise IdentityError(f"verificationMethod '{proof.verificationMethod}' not found")
        if pk_entry.type != "Ed25519VerificationKey2020":
            raise IdentityError(f"PublicKeyEntry '{pk_entry.id}' is not Ed25519VerificationKey2020")

        decoded = base58.b58decode(pk_entry.publicKeyMultibase)
        if len(decoded) >= 34 and decoded[:2] == b"\xed\x01":
            raw_pk = decoded[-32:]
        elif len(decoded) == 32:
            raw_pk = decoded
        else:
            raise InvalidParameterError(f"PublicKeyMultibase for '{pk_entry.id}' has invalid length {len(decoded)}")

        try:
            ed_pub = Ed25519PublicKey.from_public_bytes(raw_pk)
        except Exception as e:
            raise IdentityError(f"Failed to load public key bytes: {e}") from e

        doc_dict = document.model_dump(exclude={"proof"})
        message = json.dumps(doc_dict, separators=(",", ":"), sort_keys=True).encode()

        try:
            sig_bytes = base58.b58decode(proof.proofValue)
        except Exception as e:
            raise InvalidParameterError(f"Invalid base58 signature: {e}") from e

        try:
            ed_pub.verify(sig_bytes, message)
        except InvalidSignature:
            raise IdentityError("Signature verification failed")
        except Exception as e:
            raise IdentityError(f"Unexpected error during signature verification: {e}") from e

    def anchor_data(self, payload: Any, expiry: int) -> Tuple[bytes, str, bytes]:
        """
        Anchor arbitrary payload on-chain with a user-specified expiry timestamp.

        Args:
            payload: JSON-serializable data to anchor.
            expiry: Unix timestamp (seconds) when the anchor expires.

        Returns:
            A tuple of (transaction_hash, cid).

        Raises:
            InvalidParameterError: If payload serialization fails.
            NetworkError: If IPFS client is uninitialized or upload fails.
            ContractError: If the on-chain anchor transaction fails.
        """
        try:
            payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        except Exception as e:
            raise LedgerError(f"Payload not JSON-serializable: {e}") from e
        data_bytes = payload_json.encode()
        data_hash = hashlib.sha256(data_bytes).digest()

        if not self._ipfs:
            raise NetworkError("IPFS client not initialized")
        try:
            cid = self._ipfs.add_json(payload_json)
        except Exception as e:
            raise NetworkError(f"IPFS upload failed: {e}") from e

        try:
            tx_hash = self._send_tx(
                self._dac.functions.anchor,
                data_hash,
                cid,
                expiry,
                "anchored"
            )
        except Exception as e:
            raise ContractError(f"anchor tx failed: {e}") from e

        return tx_hash, cid, data_hash
    
    def get_off_chain_data(self, cid: str) -> Any:
        return self._ipfs.get_json(cid)
    
    def get_on_chain_data(self, data_hash: bytes) -> Tuple[bytes, str, int, str]:
        return self._dac.functions.get(data_hash).call()

    def verify_data(self, payload: Any) -> bool:
        """
        Verify that the given payload was anchored, is not expired, and integrity intact.

        Args:
            payload: The original JSON-serializable data.

        Returns:
            True if the anchor exists, has not expired, and the hash matches.

        Raises:
            LedgerError: If anchor is expired or status unexpected.
            ContractError: If on-chain retrieval fails.
        """
        payload_json = json.dumps(payload, separators=(",", ":"), sorted_keys=True)
        data_hash = hashlib.sha256(payload_json.encode()).digest()

        try:
            record: tuple[bytes, str, int, str] = self._dac.functions.get(data_hash)
        except Exception as e:
            raise ContractError(f"get call failed: {e}") from e

        onchain_hash, cid, expiry, status = record
        now = int(time.time())

        if now > expiry:
            raise LedgerError("Anchor has expired")
        if status != "anchored":
            raise LedgerError(f"Unexpected status: {status}")
        if onchain_hash != data_hash:
            raise LedgerError("Integrity check failed: on-chain hash mismatch")

        return True

    @classmethod
    def generate_did(cls, public_keys_multibase: List[str]) -> str:
        """
        Generate a DID by lexicographically sorting the Base58 keys,
        then joining them with '|' and hashing the result.
        DID = "did:blocka2a:" + first10chars_of_SHA256(sorted_keys_joined).hexdigest()

        Args:
            public_keys_multibase: List of Base58-encoded public keys.

        Returns:
            A DID string with 10-char fingerprint.
        """
        if not public_keys_multibase:
            raise ValueError("public_keys_multibase list cannot be empty")

        # Sort the Base58-encoded public keys lexicographically
        sorted_keys = sorted(public_keys_multibase)

        # Concatenate the sorted keys with '|' as delimiter
        joined = "|".join(sorted_keys)

        # Compute the SHA-256 hash and get the full & short hex digest
        full_digest = hashlib.sha256(joined.encode("utf-8")).hexdigest()
        short_digest = full_digest[:10]

        # Prefix with the did:blocka2a scheme
        return f"did:blocka2a:{short_digest}"

    def register_did(
        self,
        *,
        did: str,
        public_keys: List[PublicKeyEntry],
        services: List[ServiceEntry],
        capabilities: Capabilities,
        policy_constraints: PolicyConstraints,
        proof: Optional[Proof] = None,
        required_sigs_for_update: int
    ) -> Tuple[bytes, str]:
        """
        Register a new DIDDocument on-chain and upload it to IPFS.

        Args:
            did: The DID string to register.
            public_keys: List of PublicKeyEntry, including Ed25519 and BLS keys.
            services: List of ServiceEntry for the DID document.
            capabilities: Capabilities object.
            policy_constraints: PolicyConstraints object.
            proof: Optional Proof, signed by one of the Ed25519 keys.
            required_sigs_for_update: Minimum number of BLS signatures required for updates.

        Returns:
            A tuple of (transaction_hash, cid).

        Raises:
            InvalidParameterError: On bad input.
            IdentityError: If proof verification fails.
            ContractError: If on-chain call fails.
            NetworkError: If IPFS upload fails.
        """

        if required_sigs_for_update < 1:
            raise InvalidParameterError("required_sigs_for_update must be at least 1")

        if not public_keys:
            raise InvalidParameterError("public_keys list cannot be empty")

        if proof is not None:
            signer_public_key_entry = next((key for key in public_keys if key.id == proof.verification_method), None)

            if not signer_public_key_entry:
                raise IdentityError(
                    f"在 DID 文档中未找到 ID 为 '{proof.verification_method}' 的公钥，无法验证 proof。"
                )
            pubkey = crypto.multibase_to_raw_public_key(signer_public_key_entry.public_key)

            document_for_verify = DIDDocument(
                id=did,
                publicKey=public_keys,
                service=services,
                capabilities=capabilities,
                policy_constraints=policy_constraints,
                proof=None
            ).to_json().encode()

            crypto.verify(proof, document_for_verify, pubkey)

        # Build DIDDocument and verify proof if present
        document = DIDDocument(
            id = did,
            publicKey = public_keys,
            service = services,
            capabilities = capabilities,
            policy_constraints = policy_constraints,
            proof = proof
        )

        # Compute SHA-256 of the canonical JSON
        # doc_byes = document.to_json().encode()
        # doc_hash = hashlib.sha256(doc_byes).digest()

        doc_dict = document.dict(exclude_none=True)
        doc_s = json.dumps(doc_dict, separators=(",", ":"), sort_keys=True)
        doc_bytes = doc_s.encode()
        doc_hash = hashlib.sha256(doc_bytes).digest()

        # print(f"DEBUG: register_did doc_hash: {doc_hash.hex()}")
        # print(f"DEBUG: register_did JSON:{type(doc_s)} {doc_s}")

        # Upload full document to IPFS
        start = time.time()       # EVALUATION: DID Registration off-chain DID document storage
        # cid = self._ipfs.add_json(document.to_json())
        # cid = self._ipfs.add_json(doc_s)
        cid = self._ipfs.add_bytes(doc_bytes)
        end = time.time()
        print(f"off-chain DID document storage {(end - start):.6f} s")

        # print(f"DEBUG: register_did CID: {cid}")


        # On-chain register
        start = time.time()  # EVALUATION: DID Registration on-chain hash anchoring
        tx_hash = self._send_tx(
            self._agc.functions.register,
            did,
            doc_hash,
            cid,
            required_sigs_for_update,
        )
        end = time.time()
        print(f"on-chain hash anchoring {(end - start):.6f} s")

        return tx_hash, cid

    def verify(self, did: str, proof: Proof, message: Any) -> bool:
        """
        Verify a DIDDocument by fetching both documentHash and CID from the
        AgentGovernanceContract, then checking integrity and proof.

        Workflow:
          1. Call contract.resolve(did) → (ha, cid).
          2. Fetch raw bytes from IPFS using cid.
          3. Compute canonical JSON SHA-256 digest and compare to ha.
          4. Parse DIDDocument and verify the Ed25519 proof.

        Args:
            did: The DID string to verify.
            proof: The Proof object supplied by the user.
            message: The message that was signed.

        Returns:
            True if the signature is valid for the message, False otherwise.

        Raises:
            ContractError: If on-chain resolve call fails.
            NetworkError: If IPFS fetch fails.
            IdentityError: If integrity check or proof verification fails.
            InvalidParameterError: If the proof type is unsupported or formats are invalid.
        """
        # 1. Resolve DID → (ha, cid)
        try:
            ha, cid = self._agc.functions.resolve(did).call()
        except Exception as e:
            raise ContractError(f"AGC.resolve('{did}') failed: {e}") from e

        # 2. Fetch document from IPFS
        try:
            start = time.time()  # EVALUATION: DID Document Retrieval
            raw_bytes = self._ipfs.get(cid)
            end = time.time()
            print(f"DID Document Retrieval {(end - start):.6f} s")
        except Exception as e:
            raise NetworkError(f"IPFS get failed for CID {cid}: {e}") from e

        # 3. Integrity check: compute SHA-256 over canonical JSON
        try:
            doc_json = raw_bytes.decode().strip()
            doc_obj = json.loads(doc_json)
            # print(f"DEBUG: verify doc_json:{type(doc_json)} {doc_json}")
            # canonical = json.dumps(doc_obj, separators=(",", ":"), sort_keys=True).encode()
            canonical = json.dumps(doc_obj, separators=(",", ":"), sort_keys=True)
            # print(f"DEBUG: verify canonical:{type(canonical)} {canonical}")
            canonical = canonical.encode()  # Convert to bytes for hashing
            calc_ha = hashlib.sha256(canonical).digest()
            if calc_ha != ha:
                # print(f"DEBUG: verify ha: {ha.hex()}")
                # print(f"DEBUG: verify calc_ha: {calc_ha.hex()}")
                raise IdentityError("Integrity check failed: hash mismatch")
        except IdentityError:
            raise
        except Exception as e:
            raise IdentityError(f"Integrity check error: {e}") from e

        # 4. Verify proof against the provided message
        try:
            document = DIDDocument.model_validate(doc_obj)
        except Exception as e:
            raise IdentityError(f"Failed to parse DIDDocument: {e}") from e

        public_keys = document.publicKey
        signer_public_key_entry = next((key for key in public_keys if key.id == proof.verificationMethod), None)

        if not signer_public_key_entry:
            print(public_keys)
            raise IdentityError(
                f"在 DID 文档中未找到 ID 为 '{proof.verificationMethod}' 的公钥，无法验证 proof。"
            )

        # 确保 message 是字节串
        if isinstance(message, str):
            message_bytes = message.encode('utf-8')
        elif isinstance(message, bytes):
            message_bytes = message
        else:
            # 对于其他类型，可以通过序列化为JSON来处理，但最好是明确要求字节或字符串
            raise InvalidParameterError(f"Unsupported message type for verification: {type(message)}")

        pubkey = crypto.multibase_to_raw_public_key(signer_public_key_entry.publicKeyMultibase)

        if proof.type == "Ed25519Signature2020":
            if signer_public_key_entry.type != "Ed25519VerificationKey2020":
                raise IdentityError(
                    f"Key type mismatch: Expected Ed25519VerificationKey2020 for proof type {proof.type}")
            return crypto.verify(proof, message, pubkey)
        elif proof.type == "BLS256Signature2020":
            if signer_public_key_entry.type != "Bls256G2Key2020":
                raise IdentityError(f"Key type mismatch: Expected Bls256G2Key2020 for proof type {proof.type}")
            sig_bytes = base58.b58decode(proof.proofValue)
            sig_point = bn256.deserialize_g1(sig_bytes)
            return bn256.verify_single(bn256.decompress_g2(pubkey), sig_point, message, b"DAC")
        else:
            raise InvalidParameterError(f"Unsupported proof type for verification: '{proof.type}'")

    @classmethod
    def sign_task(cls, bls_sk: BLSPrivateKey, task_hash: bytes, milestone: str) -> BLSSignature:
        """
        Sign a task identification (hash + milestone) with a BLS private key.

        Args:
            bls_sk: BLS private key integer.
            task_hash: 32-byte SHA-256 hash of task metadata.
            milestone: A string identifier of the milestone.

        Returns:
            A BLSSignature for the message.
        """
        if not isinstance(bls_sk, int):
            raise InvalidParameterError("bls_sk must be BLSPrivateKey (int)")

        start = time.time()  # EVALUATION: signature generation
        key = str(task_hash) + "|" + milestone
        msg = key.encode('utf-8')

        try:
            # 从整数私钥创建 bn256.SecretKey 对象
            secret_key = bn256.SecretKey(bls_sk)

            # 使用 bn256 库对消息进行签名
            sig_point: bn256.Signature = bn256.sign(msg, secret_key, domain=b"DAC")

            # 签名结果是一个 PointG1 元组 (FQ, FQ)，需要将其序列化为字节流。
            # 采用未压缩格式：32字节x坐标 || 32字节y坐标
            x_bytes = sig_point[0].n.to_bytes(32, "big")
            y_bytes = sig_point[1].n.to_bytes(32, "big")

            sig = BLSSignature(x_bytes + y_bytes)

        except Exception as e:
            # 捕获签名过程中可能出现的任何错误
            raise RuntimeError(f"生成 BN256 签名失败: {e}") from e

        end = time.time()
        print(f"signature generation {(end - start):.6f} s")
        return sig

    def request_resource(self, did: str, resource_identifier: str, action_identifier: str) -> AccessToken:
        """
        Requests access to a resource by calling the issueToken function on the ACC.
        If successful, it constructs and returns a token object.

        Args:
            did: The DID of the agent requesting access.
            resource_identifier: The identifier of the resource being requested.
            action_identifier: The action being requested on the resource.

        Returns:
            A token dictionary containing all necessary information for verification.

        Raises:
            ContractError: If the transaction fails or the event is not found.
            IdentityError: If the client is not configured with a private key.
        """
        if not self._acct:
            raise IdentityError("A private key is required to request a resource.")

        # Call the issueToken function on the smart contract
        try:
            tx_hash = self._send_tx(
                self._acc.functions.evaluate,
                did,
                resource_identifier,
                action_identifier,
            )
            receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash)
            if receipt.status != 1:
                raise ContractError(f"Token issuance transaction failed with hash: {tx_hash.hex()}")
        except Exception as e:
            raise ContractError(f"Failed to send issueToken transaction: {e}") from e

        # Process the logs to find the TokenIssued event and extract its data
        logs = self._acc.events.TokenIssued().process_receipt(receipt)
        if not logs:
            raise ContractError("TokenIssued event not found in transaction receipt.")

        event_args = logs[0]['args']
        expiry = event_args['expiry']

        # Construct the token object with data from the request and the event
        token = AccessToken(
            agentDID = did,
            actionIdentifier = action_identifier,
            resourceIdentifier = resource_identifier,
            expiry = expiry,
        )
        return token
    
    
    def agc_update(
        self,
        did: str,
        new_document_hash: bytes,
        agg_sig: List[int],  # [x1, x2, y1, y2] 格式的签名
        pks_mask: int
    ) -> HexBytes:
        """更新 DID 文档"""
        tx = self._agc.functions.update(
            did,
            new_document_hash,
            agg_sig,
            pks_mask
        ).build_transaction({
            'from': self._account.address,
            'gas': self._default_gas,
            'nonce': self._web3.eth.get_transaction_count(self._account.address),
        })
        
        signed_tx = self._account.sign_transaction(tx)
        return self._web3.eth.send_raw_transaction(signed_tx.rawTransaction)
    
    def agc_resolve(self, did: str) -> Tuple[bytes, str]:
        """解析 DID 信息"""
        return self._agc.functions.resolve(did).call()
    
    def agc_revoke(
        self,
        did: str,
        agg_sig: List[int],  # [x1, x2, y1, y2] 格式的签名
        pks_mask: int
    ) -> HexBytes:
        """撤销 DID"""
        tx = self._agc.functions.revoke(
            did,
            agg_sig,
            pks_mask
        ).build_transaction({
            'from': self._account.address,
            'gas': self._default_gas,
            'nonce': self._web3.eth.get_transaction_count(self._account.address),
        })
        
        signed_tx = self._account.sign_transaction(tx)
        return self._web3.eth.send_raw_transaction(signed_tx.rawTransaction)