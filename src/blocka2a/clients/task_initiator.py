import hashlib
import json
from typing import List, Tuple, Optional
import time
from src.blocka2a.clients.base_client import BaseClient
from src.blocka2a.clients.errors import InvalidParameterError, NetworkError, ContractError
from src.blocka2a.contracts import data_anchoring_contract
from src.blocka2a.types import TaskMetadata

class TaskInitiator(BaseClient):
    """Client for initiating tasks and anchoring their metadata on‐chain."""

    def __init__(
        self,
        rpc_endpoint: str,
        initiator_did: str,
        data_anchoring_address: str,
        private_key: Optional[str] = None,
        ipfs_gateway: Optional[str] = None,
        default_gas: int = 2_000_000,
    ) -> None:
        """
        Initialize a TaskInitiator instance.

        Args:
            rpc_endpoint: URL of the Ethereum JSON-RPC endpoint.
            initiator_did: DID of the task initiator.
            data_anchoring_address: Address of the deployed DataAnchoringContract.
            private_key: Hex string of an EOA private key for signing txs.
                         If None, write operations are disabled.
            ipfs_gateway: URL or multi-addr for the IPFS API; if None, off-chain ops disabled.
            default_gas: Default gas limit for transactions.

        Raises:
            InvalidParameterError: If initiator_did is empty or dac_address invalid.
        """
        # BaseClient init will set up _w3, _acct, _ipfs, _gas, _chain_id
        super().__init__(
            rpc_endpoint=rpc_endpoint,
            private_key=private_key,
            ipfs_gateway=ipfs_gateway,
            default_gas=default_gas,
        )

        if not initiator_did:
            raise InvalidParameterError("initiator_did must be provided")
        self._initiator = initiator_did

        self._dac = self._load_contract(data_anchoring_contract.get_contract, data_anchoring_address)

    def initiate_task(self, participants: List[str], description: str, deadline: int) -> Tuple[str, bytes, bytes]:
        """
        Initiate a new task by anchoring its metadata on IPFS and on-chain.

        Workflow:
          1. Build TaskMetadata.
          2. Serialize to canonical JSON, compute SHA-256 hash.
          3. Upload JSON to IPFS → cid.
          4. Call DataAnchoringContract.anchorData(hash, cid, deadline, "initiated").

        Args:
            participants: List of participant DIDs.
            description: Detailed task description.
            deadline: Unix timestamp (seconds) indicating the task deadline.

        Returns:
            A tuple of (cid, transaction_hash).

        Raises:
            InvalidParameterError: If serialization fails.
            NetworkError: If IPFS client not initialized or upload fails.
            ContractError: If the on-chain call fails or reverts.
        """
        # 1. Build metadata
        task_init_start = time.time()
        meta = TaskMetadata(
            initiator = self._initiator,
            participants = participants,
            description = description,
            deadline = deadline,
        )
        

        # 2. Serialize and hash
        try:
            # meta_dict = meta.dict()
            meta_dict = meta  # Convert to dict for serialization
            json_str = json.dumps(meta_dict, separators=(",", ":"), sort_keys=True)
        except Exception as e:
            raise InvalidParameterError(f"Failed to serialize TaskMetadata: {e}") from e

        data_bytes = json_str.encode()
        data_hash = hashlib.sha256(data_bytes).digest()

        # 3. Upload to IPFS
        if not self._ipfs:
            raise NetworkError("IPFS client not initialized")
        try:
            start = time.time()     # EVALUATION: task off-chain data anchoring
            cid = self._ipfs.add_json(json_str)
            end = time.time()
            print(f"task off-chain data anchoring {end - start:.6f} s")
        except Exception as e:
            raise NetworkError(f"IPFS upload failed: {e}") from e

        # 4. Anchor on-chain
        try:
            start = time.time()  # EVALUATION: task on-chain anchoring
            tx_hash = self._send_tx(
                self._dac.functions.anchor,
                data_hash,
                cid,
                deadline,
                "initiated",
            )
            end = time.time()
            print(f"task on-chain anchoring {end - start:.6f} s")
        except Exception as e:
            raise ContractError(f"anchor transaction failed: {e}") from e

        task_init_end = time.time()
        print(f"Task initiated in {task_init_end - task_init_start:.6f} s")
        return cid, tx_hash, data_hash