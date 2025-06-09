"""
BlockA2A Client Subpackage.

This package provides the core client classes for interacting with the
BlockA2A protocol, including DID operations, data anchoring, task initiation,
and BLS signature aggregation.
"""

from .base_client import BaseClient
from .blocka2a_client import BlockA2AClient
from .signature_aggregator import SignatureAggregator
from .task_initiator import TaskInitiator
from .errors import (
    BlockA2AError,
    InvalidParameterError,
    NotFoundError,
    UnauthorizedError,
    NetworkError,
    TimeoutError,
    IdentityError,
    LedgerError,
    ContractError,
    TransactionError,
    IdentityNotFound,
)

__all__ = [
    "BaseClient",
    "BlockA2AClient",
    "SignatureAggregator",
    "TaskInitiator",
    "BlockA2AError",
    "InvalidParameterError",
    "NotFoundError",
    "UnauthorizedError",
    "NetworkError",
    "TimeoutError",
    "IdentityError",
    "LedgerError",
    "ContractError",
    "TransactionError",
    "IdentityNotFound",
]