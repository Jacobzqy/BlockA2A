from typing import List, Any, Callable

from web3.contract import Contract
from web3.contract.contract import ContractFunction
from web3.types import ChecksumAddress, TxParams, Nonce, Wei, TxReceipt
from web3 import Web3, HTTPProvider
from src.blocka2a.clients.errors import InvalidParameterError, ContractError, TransactionError, UnauthorizedError
from src.blocka2a.types import BLSSignature
from py_ecc.bls import G2ProofOfPossession
from src.blocka2a.contracts import provenance_contract

class SignatureAggregator:
    """Handles BLS signature aggregation and on-chain submission for task validation."""
    def __init__(
        self,
        rpc_endpoint: str,
        private_key: str,
        provenance_address: str,
        default_gas: int = 2_000_000
    ) -> None:
        """
        Initializes a new SignatureAggregator.

        Args:
            rpc_endpoint: URL of the Ethereum JSON-RPC endpoint.
            private_key: Hex string of the EOA private key for signing transactions.
                         If None, write operations will be disabled.
            provenance_address: Address of the deployed ProvenanceContract.
            default_gas: Default gas limit for transactions.

        Raises:
            InvalidParameterError: If provenance_address is not a valid Ethereum address.
        """
        # Web3 setup
        self._w3 = Web3(HTTPProvider(rpc_endpoint, request_kwargs={"timeout": 30}))
        self._acct = self._w3.eth.account.from_key(private_key)
        self._gas = default_gas
        self._chain_id = self._w3.eth.chain_id

        # ProvenanceContract instance
        if not Web3.is_address(provenance_address):
            raise InvalidParameterError(f"Invalid provenance contract address: {provenance_address}")
        checksum_addr: ChecksumAddress = Web3.to_checksum_address(provenance_address)
        self._prov: Contract = provenance_contract.get_contract(self._w3, checksum_addr)

    def _send_tx(self, fn: Callable[..., ContractFunction], *args: Any, value: int = 0) -> bytes:
        """
        Builds, signs, sends a transaction and waits for its receipt.

        Args:
            fn: A contract.functions.<method> callable.
            *args: Arguments to pass to the method.
            value: Amount of Wei to send with the transaction.

        Returns:
            The transaction hash as bytes.

        Raises:
            UnauthorizedError: If no private key was provided.
            TimeoutError: If waiting for the receipt times out.
            TransactionError: If the transaction reverts or fails.
        """
        if self._acct is None:
            raise UnauthorizedError("No private key provided; cannot send transactions.")

        # Prepare transaction parameters
        tx_params: TxParams = {
            "from": self._acct.address,
            "nonce": Nonce(self._w3.eth.get_transaction_count(self._acct.address)),
            "gas": Wei(self._gas),
            "value": Wei(value),
            "chainId": self._chain_id,
        }

        # Build and sign
        tx = fn(*args).build_transaction(tx_params)
        signed = self._acct.sign_transaction(tx)

        # Send and wait
        try:
            tx_hash = self._w3.eth.send_raw_transaction(signed.rawTransaction)
            receipt: TxReceipt = self._w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        except TimeoutError as e:
            raise TimeoutError("Transaction receipt wait timed out") from e
        except Exception as e:
            raise TransactionError(f"Transaction failed: {e}", getattr(e, "tx_hash", None)) from e

        # Check status
        if receipt["status"] != 1:
            raise TransactionError("Transaction reverted", receipt["transactionHash"].hex())
        return receipt["transactionHash"]

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