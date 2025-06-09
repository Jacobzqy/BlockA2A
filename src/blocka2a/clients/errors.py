class BlockA2AError(Exception):
    """
    Base class for all BlockA2A SDK errors.

    This exception serves as the root of the BlockA2A SDK error hierarchy.
    """
    pass


class InvalidParameterError(BlockA2AError):
    """
    Raised when a provided parameter is invalid or malformed.

    This indicates that the arguments passed to a method do not meet
    the expected criteria or format.
    """
    pass


class NotFoundError(BlockA2AError):
    """
    Raised when a requested resource does not exist.

    Examples include attempting to retrieve a non-existent DID or task.
    """
    pass


class UnauthorizedError(BlockA2AError):
    """
    Raised when an operation is attempted without proper authorization.

    This typically means that no signing key was provided for a
    write operation.
    """
    pass


class NetworkError(BlockA2AError):
    """
    Raised on network-level failures.

    Examples include RPC connectivity issues or IPFS API errors.
    """
    pass


class TimeoutError(BlockA2AError):
    """
    Raised when an operation times out.

    This can occur when waiting for a transaction receipt or an HTTP request.
    """
    pass


class IdentityError(BlockA2AError):
    """
    Raised for identity-layer failures.

    Examples include DID generation errors or signature verification failures.
    """
    pass


class LedgerError(BlockA2AError):
    """
    Raised for ledger-layer failures.

    Examples include task initiation errors or state validation failures.
    """
    pass


class ContractError(BlockA2AError):
    """
    Base exception for smart contract invocation errors.

    This serves as a parent for errors arising from on-chain calls.
    """
    pass


class TransactionError(ContractError):
    """
    Raised when an on-chain transaction reverts or fails.

    Attributes:
        tx_hash: Optional blockchain transaction hash string associated
                 with the failed transaction.
    """

    def __init__(self, message: str, tx_hash: str | None = None):
        """
        Initialize a TransactionError.

        Args:
            message: Description of the error.
            tx_hash: Optional transaction hash for reference.
        """
        super().__init__(message)
        self.tx_hash = tx_hash


# Convenience alias
IdentityNotFound = IdentityError
