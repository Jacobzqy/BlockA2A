from typing import Optional, Callable, Any

from web3 import Web3, HTTPProvider
from web3.contract.contract import ContractFunction, Contract
from web3.types import TxParams, Nonce, Wei, TxReceipt, ChecksumAddress

from src.blocka2a.clients.errors import UnauthorizedError, TransactionError, InvalidParameterError
from src.blocka2a.utils.ipfs import IPFSClient


class BaseClient:
    """Common functionality for all BlockA2A clients: Web3, account, IPFS and tx sending."""

    def __init__(
        self,
        *,
        rpc_endpoint: str,
        private_key: Optional[str],
        ipfs_gateway: Optional[str],
        default_gas: int = 2_000_000
    ) -> None:
        """
        Initialize the BaseClient.

        Args:
            rpc_endpoint: JSON-RPC URL for an Ethereum node.
            private_key: Hex string of the EOA private key, or None for read-only mode.
            ipfs_gateway: URL or multi‐addr of the IPFS API endpoint; if None, off-chain ops are disabled.
            default_gas: Default gas limit for transactions.

        Raises:
            ValueError: If rpc_endpoint is empty.
        """
        if not rpc_endpoint:
            raise ValueError("rpc_endpoint must be provided")

        # Web3 and account setup
        self._w3 = Web3(HTTPProvider(rpc_endpoint, request_kwargs={"timeout": 30}))
        self._acct = self._w3.eth.account.from_key(private_key) if private_key else None
        self._gas = default_gas
        self._chain_id = self._w3.eth.chain_id

        # IPFS client (optional)
        self._ipfs = IPFSClient(ipfs_gateway) if ipfs_gateway else None

    def _send_tx(self, fn: Callable[..., ContractFunction], *args: Any, value: int = 0) -> bytes:
        """
        Build, sign, send a transaction and wait for its receipt.

        Args:
            fn: A `contract.functions.<method>` reference.
            *args: Arguments for the call.
            value: Wei to send alongside (default 0).

        Returns:
            The transaction hash (HexBytes).

        Raises:
            UnauthorizedError: no private key configured.
            TimeoutError: timed out waiting for the receipt.
            TransactionError: reverted or other error.
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

        # Build and sign the transaction
        tx = fn(*args).build_transaction(tx_params)
        signed = self._acct.sign_transaction(tx)

        # Send the raw transaction and wait for receipt
        try:
            tx_hash = self._w3.eth.send_raw_transaction(signed.rawTransaction)
            receipt: TxReceipt = self._w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        except TimeoutError as e:
            raise TimeoutError("Transaction receipt wait timed out") from e
        except Exception as e:
            raise TransactionError(f"Transaction failed: {e}", getattr(e, "tx_hash", None)) from e

        # Check the status code in the receipt
        if receipt["status"] != 1:
            raise TransactionError("Transaction reverted", receipt["transactionHash"].hex())
        return receipt["transactionHash"]

    def _load_contract(self, getter: Callable[[Web3, Any], Contract], address: str) -> Contract:
        """
        Validate and checksum an address, then load a Web3.py Contract via the provided stub.

        Args:
            getter: A function `get_contract(w3, address)` that returns a Contract.
            address: Hex string of the contract address.

        Returns:
            A Web3.py Contract instance.

        Raises:
            InvalidParameterError: If the address is not a valid Ethereum address.
        """
        if not Web3.is_address(address):
            raise InvalidParameterError(f"Invalid contract address: {address}")
        checksum_addr: ChecksumAddress = Web3.to_checksum_address(address)
        return getter(self._w3, checksum_addr)