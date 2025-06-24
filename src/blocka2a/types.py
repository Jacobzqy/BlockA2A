from __future__ import annotations

from datetime import datetime
from typing import List
from pydantic import BaseModel
from eth_typing import BLSPubkey, BLSPrivateKey, BLSSignature
import json

class PublicKeyEntry(BaseModel):
    """Represents a single public key within a DID Document.

    This structure is used to associate a cryptographic key with the DID,
    enabling verification of signatures and other cryptographic operations.
    In the BlockA2A context, these include Ed25519 keys for document proofs
    and BLS keys for on-chain consensus.

    Attributes:
        id (str): A full URI pointing to this specific key, typically the DID
            followed by a fragment (e.g., "did:blocka2a:123#keys-1").
        type (str): The cryptographic suite used for the key, such as
            "Ed25519VerificationKey2020" or "Bls12381G1Key2020".
        publicKeyMultibase (str): The public key material, encoded in Base58BTC
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
        id (str): A unique identifier for the service within the document,
            formatted as a URI fragment (e.g., "did:blocka2a:123#service-1").
        type (str): The type of the service being described (e.g., "AgentWebService").
        serviceEndpoint (str): The URL or URI where the service can be accessed.
    """
    id: str
    type: str
    serviceEndpoint: str

class Capabilities(BaseModel):
    """Describes the functional capabilities of the BlockA2A agent.

    This object specifies what the agent can do, which models it supports,
    and what permissions it operates with.

    Attributes:
        supportedModels (List[str]): A list of AI or computation models that
            the agent is capable of running (e.g., ["gpt-4", "llama3-70b"]).
        maxComputeTime (str): A string representing the maximum duration in seconds
            the agent will spend on a single computation task (e.g., "600").
        permissions (List[str]): A list of explicit permissions granted to the
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
        allowed_interaction_hours (str): A time window, typically in UTC,
            during which the agent is available for tasks (e.g., "09:00-17:00").
        max_data_size (str): A string representing the maximum data payload size
            in bytes that the agent will accept for a task (e.g., "1048576" for 1MB).
    """
    allowed_interaction_hours: str
    max_data_size: str

class Proof(BaseModel):
    """Contains a cryptographic proof to verify the DID Document's authenticity.

    The proof ensures the integrity of the DID Document and links it to a
    specific controller key. In this system, it is typically an Ed25519
    signature over the canonicalized document.

    Attributes:
        type (str): The signature suite used to create the proof, such as
            "Ed25519Signature2020".
        created (datetime): The UTC timestamp in ISO 8601 format indicating
            when the proof was generated.
        verificationMethod (str): The id of the PublicKeyEntry within this
            document that must be used to verify the proof.
        proofValue (str): The Base58-encoded signature value.
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
        id (str): The unique Decentralized Identifier (DID) string.
        publicKey (List[PublicKeyEntry]): A list of public keys controlled by the DID.
        service (List[ServiceEntry]): A list of service endpoints for interaction.
        capabilities (Capabilities): The agent's functional capabilities.
        policy_constraints (PolicyConstraints): The agent's operational rules.
        proof (Optional[Proof]): An optional proof to verify the document's
            integrity. Can be None during initial creation.
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
        initiator (str): The DID of the entity that created and proposed the task.
        participants (List[str]): A list of DIDs of the agents assigned to the task.
        description (str): A human-readable description of the task's objective.
        deadline (int): A Unix timestamp (seconds) by which the task must be completed.
    """
    initiator: str
    participants: List[str]
    description: str
    deadline: int
