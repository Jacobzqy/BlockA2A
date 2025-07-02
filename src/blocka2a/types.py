"""Defines the core data structures and Pydantic models for the BlockA2A system.

This module contains the central types used for representing Decentralized
Identifiers (DIDs), tasks, policies, and other key entities within the
BlockA2A ecosystem. These models ensure data consistency, validation, and
provide serialization/deserialization capabilities.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import List, Dict, NewType
from pydantic import BaseModel
from eth_typing import BLSPubkey, BLSPrivateKey, BLSSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

# Define Ed25519Signature as a new type based on bytes with validation
class Ed25519Signature(bytes):
    def __new__(cls, data: bytes):
        if len(data) != 64:
            raise ValueError(f"Ed25519 signature must be 64 bytes, got {len(data)}")
        return super().__new__(cls, data)


class PublicKeyEntry(BaseModel):
    """Represents a single public key within a DID Document.

    This structure is used to associate a cryptographic key with the DID,
    enabling verification of signatures and other cryptographic operations.
    In the BlockA2A context, these include Ed25519 keys for document proofs
    and BLS keys for on-chain consensus.

    Attributes:
        id: A full URI pointing to this specific key, typically the DID
            followed by a fragment (e.g., "did:blocka2a:1a2b3c4d5e#keys-1").
        type: The cryptographic suite used for the key, such as
            "Ed25519VerificationKey2020".
        publicKeyMultibase: The public key material, encoded in Base58BTC
            multibase format (starting with 'z').
    """
    id: str
    type: str
    publicKeyMultibase: str


class ServiceEntry(BaseModel):
    """Defines a service endpoint associated with a DID.

    Services can be any type of endpoint for interacting with the DID's subject
    (the agent), such as a web API for task assignment or a communication hub.

    Attributes:
        id: A unique identifier for the service within the document,
            formatted as a URI fragment (e.g., "did:blocka2a:1a2b3c4d5e#service-1").
        type: The type of the service being described (e.g., "AgentWebService").
        serviceEndpoint: The URL or URI where the service can be accessed.
    """
    id: str
    type: str
    serviceEndpoint: str


class Capabilities(BaseModel):
    """Describes the functional capabilities of the BlockA2A agent.

    This object specifies what the agent can do, which models it supports,
    and what permissions it operates with.

    Attributes:
        supportedModels: A list of AI or computation models that
            the agent is capable of running (e.g., ["gpt-4", "llama3-70b"]).
        maxComputeTime: A string representing the maximum duration in seconds
            the agent will spend on a single computation task (e.g., "600").
        permissions: A list of explicit permissions granted to the
            agent (e.g., ["read", "execute"]).
    """
    supportedModels: List[str]
    maxComputeTime: str
    permissions: List[str]


class PolicyConstraints(BaseModel):
    """Defines operational rules and limits for the BlockA2A agent.

    These constraints act as a policy layer, governing how and when the agent
    can be interacted with.

    Attributes:
        allowed_interaction_hours: A time window, typically in UTC,
            during which the agent is available for tasks (e.g., "09:00-17:00").
        max_data_size: A string representing the maximum data payload size
            that the agent will accept for a task (e.g., "10MB").
    """
    allowed_interaction_hours: str
    max_data_size: str


class Proof(BaseModel):
    """Contains a cryptographic proof to verify the DID Document's authenticity.

    The proof ensures the integrity of the DID Document and links it to a
    specific controller key. In this system, it is typically an Ed25519
    signature over the canonicalized document.

    Attributes:
        type: The signature suite used to create the proof, such as
            "Ed25519Signature2020".
        created: The UTC timestamp in ISO 8601 format indicating
            when the proof was generated.
        verificationMethod: The id of the PublicKeyEntry within this
            document that must be used to verify the proof.
        proofValue: The Base58-encoded signature value.
    """
    type: str
    created: datetime
    verificationMethod: str
    proofValue: str


class DIDDocument(BaseModel):
    """The central data structure for a BlockA2A Decentralized Identity.

    This document aggregates all information related to an agent's identity,
    including its cryptographic keys, service endpoints, capabilities, and
    policies. The document is stored on IPFS, and its hash is anchored on-chain.

    Attributes:
        id: The unique Decentralized Identifier (DID) string.
        publicKey: A list of public keys controlled by the DID.
        service: A list of service endpoints for interaction.
        capabilities: The agent's functional capabilities.
        policy_constraints: The agent's operational rules.
        proof: An optional proof to verify the document's integrity. Can be
            None during initial creation.
    """
    id: str
    publicKey: List[PublicKeyEntry]
    service: List[ServiceEntry]
    capabilities: Capabilities
    policy_constraints: PolicyConstraints
    proof: Proof | None = None

    def to_json(self, *, indent: int | None = None) -> str:
        """Serializes the DID Document to a canonical JSON string.

        Args:
            indent: If provided, formats the JSON with the specified indent level.

        Returns:
            A string containing the sorted, canonical JSON representation.
        """
        model_dict = self.model_dump(
            mode='json',
            by_alias=True,
            exclude_none=True
        )
        return json.dumps(model_dict, indent=indent, sort_keys=True)

    @classmethod
    def from_json(cls, data: str) -> "DIDDocument":
        """Deserializes a DID Document from a JSON string.

        Args:
            data: The JSON string to parse.

        Returns:
            A new instance of the DIDDocument class.
        """
        return cls.model_validate_json(data)


class TaskMetadata(BaseModel):
    """Defines the metadata for a task to be performed by agents.

    This structure represents the core information about a task, which can be
    hashed and signed by participating agents to signal agreement or milestone
    completion.

    Attributes:
        initiator: The DID of the entity that created and proposed the task.
        participants: A list of DIDs of the agents assigned to the task.
        description: A human-readable description of the task's objective.
        deadline: A Unix timestamp (seconds) by which the task must be completed.
    """
    initiator: str
    participants: List[str]
    description: str
    deadline: int


class AccessToken(BaseModel):
    """Represents a short-lived, single-purpose access token.

    This token grants a specific agent temporary, fine-grained permission to
    perform an action on a resource.

    Attributes:
        agentDID: The DID of the agent being granted access.
        actionIdentifier: The specific action permitted (e.g., "executeTask").
        resourceIdentifier: The resource the action applies to (e.g., a task ID).
        expiry: A Unix timestamp indicating when the token expires.
    """
    agentDID: str
    actionIdentifier: str
    resourceIdentifier: str
    expiry: int


class Policy(BaseModel):
    """Defines a generic, extensible policy rule.

    This structure allows for flexible policy definitions where the `policy_type`
    specifies the kind of rule, and `policy_param` provides its configuration.

    Attributes:
        policy_type: A string identifying the type of policy (e.g., "temporal").
        policy_param: A list of key-value dictionaries containing the parameters
            for the policy (e.g., `[{"validafter": "100101"}, {"validbefore": "120100"}]`).
    """
    policy_type: str
    policy_param: List[Dict[str, str]]