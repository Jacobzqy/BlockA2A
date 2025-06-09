from typing import List, Optional

from src.blocka2a.clients.errors import InvalidParameterError, ContractError
from src.blocka2a.types import BLSSignature
from src.blocka2a.clients.base_client import BaseClient
from py_ecc.bls import G2ProofOfPossession
from src.blocka2a.contracts import provenance_contract

class SignatureAggregator(BaseClient):
    """Handles BLS signature aggregation and on-chain submission for task validation."""

    def __init__(
        self,
        rpc_endpoint: str,
        provenance_address: str,
        private_key: Optional[str] = None,
        ipfs_gateway: Optional[str] = None,
        default_gas: int = 2_000_000
    ) -> None:
        """
        Initialize a SignatureAggregator.

        Args:
            rpc_endpoint: Ethereum JSON-RPC endpoint URL.
            provenance_address: Address of the deployed ProvenanceContract.
            private_key: Hex string of an EOA private key for sending transactions.
                         If None, only read-only calls are allowed.
            ipfs_gateway: URL or multi-addr for the IPFS API; if None, off-chain ops disabled.
            default_gas: Default gas limit for transactions.

        Raises:
            InvalidParameterError: If provenance_address is not a valid Ethereum address.
        """
        # Initialize Web3, account and IPFS via BaseClient
        super().__init__(
            rpc_endpoint=rpc_endpoint,
            private_key=private_key,
            ipfs_gateway=ipfs_gateway,
            default_gas=default_gas,
        )

        self._prov = self._load_contract(provenance_contract.get_contract, provenance_address)

    @staticmethod
    def aggregate(sigs: List[BLSSignature]) -> BLSSignature:
        """
        Aggregates multiple BLS signatures into a single signature.

        Args:
            sigs: A list of BLSSignature, each 96 bytes.

        Returns:
            A single BLSSignature representing the aggregate.

        Raises:
            InvalidParameterError: If any signature is invalid.
        """

        if not sigs:
            raise InvalidParameterError("No signatures provided for aggregation")

        try:
            agg_sig: BLSSignature = G2ProofOfPossession.Aggregate(sigs)
        except Exception as e:
            raise InvalidParameterError(f"BLS aggregation validation failed: {e}") from e

        return agg_sig

    def submit_task_validation(self, task_hash: bytes, aggregate_signature: BLSSignature, milestone: str, dids: List[str]) -> bytes:
        """
        Submits a BLS aggregate signature for a task milestone to the ProvenanceContract.

        Args:
            task_hash: 32-byte SHA256 hash of the task metadata.
            aggregate_signature: The BLSSignature returned by aggregate().
            milestone: Identifier for the milestone being validated.
            dids: List of DIDs whose keys participated in the signature.

        Returns:
            The transaction hash as HexBytes.

        Raises:
            InvalidParameterError: If inputs are malformed.
            ContractError: If the on-chain call fails or reverts.
        """
        if not isinstance(aggregate_signature, bytes):
            raise InvalidParameterError("aggregate_signature must be BLSSignature")
        if not dids:
            raise InvalidParameterError("dids list cannot be empty")

        try:
            tx_hash = self._send_tx(
                self._prov.functions.updateTask,
                aggregate_signature,
                task_hash,
                milestone,
                dids
            )
        except Exception as e:
            raise ContractError(f"updateTask tx failed: {e}") from e

        return tx_hash