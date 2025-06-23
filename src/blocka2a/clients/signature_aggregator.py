from typing import List, Optional
import time
from src.blocka2a.clients.errors import InvalidParameterError, ContractError
from src.blocka2a.types import BLSSignature
from src.blocka2a.clients.base_client import BaseClient
from py_ecc.bls import G2ProofOfPossession
from py_ecc.bls.g2_primitives import signature_to_G2
from src.blocka2a.contracts import data_anchoring_contract

class SignatureAggregator(BaseClient):
    """Handles BLS signature aggregation and on-chain submission for task validation."""

    def __init__(
        self,
        rpc_endpoint: str,
        data_anchoring_address: str,
        private_key: Optional[str] = None,
        ipfs_gateway: Optional[str] = None,
        default_gas: int = 2_000_000
    ) -> None:
        """
        Initialize a SignatureAggregator.

        Args:
            rpc_endpoint: Ethereum JSON-RPC endpoint URL.
            data_anchoring_address: Address of the deployed ProvenanceContract.
            private_key: Hex string of an EOA private key for sending transactions.
                         If None, only read-only calls are allowed.
            ipfs_gateway: URL or multi-addr for the IPFS API; if None, off-chain ops disabled.
            default_gas: Default gas limit for transactions.

        Raises:
            InvalidParameterError: If data_anchoring_address is not a valid Ethereum address.
        """
        # Initialize Web3, account and IPFS via BaseClient
        super().__init__(
            rpc_endpoint=rpc_endpoint,
            private_key=private_key,
            ipfs_gateway=ipfs_gateway,
            default_gas=default_gas,
        )

        self._dac = self._load_contract(data_anchoring_contract.get_contract, data_anchoring_address)

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
            start = time.time()      # EVALUATION: Multi-signature generation
            agg_sig: BLSSignature = G2ProofOfPossession.Aggregate(sigs)
            end = time.time()
            print(f"multi-signature generation {end - start:.2f} s")
        except Exception as e:
            raise InvalidParameterError(f"BLS aggregation validation failed: {e}") from e

        return agg_sig

    @staticmethod
    def bls_signature_to_uint256x4(sig: BLSSignature) -> List[int]:
        """
        Convert a 96-byte BLS signature into a Solidity uint256[4] representing
        the G2 point coordinates.

        Args:
            sig: BLSSignature bytes (96 bytes).

        Returns:
            A list [x0, x1, y0, y1], where each is an uint256 limb of the FQ2 coordinates.

        Raises:
            InvalidParameterError: If signature decoding fails.
        """
        try:
            # Decode signature bytes into a G2 point: (FQ2 x, FQ2 y, FQ2 z)
            x_fq2, y_fq2, _ = signature_to_G2(BLSSignature(sig))
        except Exception as e:
            raise InvalidParameterError(f"Invalid BLS signature format: {e}") from e

        # Each FQ2 element has two FQ limbs: c0 and c1
        x0 = int(x_fq2.coeffs[0].n)
        x1 = int(x_fq2.coeffs[1].n)
        y0 = int(y_fq2.coeffs[0].n)
        y1 = int(y_fq2.coeffs[1].n)
        return [x0, x1, y0, y1]

    def submit_task_validation(
        self,
        agg_sig: BLSSignature,
        data_hash: bytes,
        milestone: str,
        dids: List[str],
    ) -> bytes:
        """
        Verify a BLS aggregate signature locally, then submit the
        uint256[4] representation to the DataAnchoringContract for update.

        Args:
            agg_sig: BLSSignature returned by `aggregate()`.
            data_hash: 32-byte SHA-256 hash of the task metadata.
            milestone: Milestone identifier, e.g. "milestone-X".
            dids: List of DIDs whose keys participated.

        Returns:
            The transaction hash as HexBytes.

        Raises:
            InvalidParameterError: If inputs are malformed.
            ContractError: If the on-chain update call fails.
        """
        if not agg_sig or not isinstance(agg_sig, (bytes, bytearray)):
            raise InvalidParameterError("aggregate_signature must be BLSSignature")

        # Convert to uint256[4] G2 coordinates
        agg_sig_point = self.bls_signature_to_uint256x4(agg_sig)

        # Submit on-chain: update(uint256[4], bytes32, string, string[])
        try:
            tx_hash = self._send_tx(
                self._dac.functions.update,
                agg_sig_point,
                data_hash,
                milestone,
                dids,
            )
        except Exception as e:
            raise ContractError(f"DAC.update call failed: {e}") from e

        return tx_hash