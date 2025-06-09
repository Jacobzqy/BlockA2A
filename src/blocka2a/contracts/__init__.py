"""
BlockA2A Contracts Subpackage.

This package provides Python stubs for Web3.py integration with the
on‐chain smart contracts used by the BlockA2A protocol.
"""

from web3 import Web3
from web3.contract import Contract
from web3.types import Address, ChecksumAddress, ENS
from typing import Union

from .access_control_contract import get_contract as get_access_control_contract
from .interaction_logic_contract import get_contract as get_interaction_logic_contract
from .agent_governance_contract import get_contract as get_agent_governance_contract
from .data_anchoring_contract import get_contract as get_data_anchoring_contract

__all__ = [
    "get_access_control_contract",
    "get_interaction_logic_contract",
    "get_agent_governance_contract",
    "get_data_anchoring_contract",
    "load_access_control",
    "load_interaction_logic",
    "load_agent_governance",
    "load_data_anchoring",
]


def load_access_control(
    w3: Web3,
    address: Union[Address, ChecksumAddress, ENS],
) -> Contract:
    """
    Convenience loader for the AccessControlContract.

    Args:
        w3: Initialized Web3 instance.
        address: On‐chain address of the deployed contract.

    Returns:
        A Web3.py Contract instance.
    """
    return get_access_control_contract(w3, address)


def load_interaction_logic(
    w3: Web3,
    address: Union[Address, ChecksumAddress, ENS],
) -> Contract:
    """
    Convenience loader for the InteractionLogicContract.

    Args:
        w3: Initialized Web3 instance.
        address: On‐chain address of the deployed contract.

    Returns:
        A Web3.py Contract instance.
    """
    return get_interaction_logic_contract(w3, address)


def load_agent_governance(
    w3: Web3,
    address: Union[Address, ChecksumAddress, ENS],
) -> Contract:
    """
    Convenience loader for the AgentGovernanceContract.

    Args:
        w3: Initialized Web3 instance.
        address: On‐chain address of the deployed contract.

    Returns:
        A Web3.py Contract instance.
    """
    return get_agent_governance_contract(w3, address)


def load_data_anchoring(
    w3: Web3,
    address: Union[Address, ChecksumAddress, ENS],
) -> Contract:
    """
    Convenience loader for the DataAnchoringContract.

    Args:
        w3: Initialized Web3 instance.
        address: On‐chain address of the deployed DataAnchoringContract.

    Returns:
        A Web3.py Contract instance.
    """
    return get_data_anchoring_contract(w3, address)