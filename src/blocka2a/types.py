from __future__ import annotations

from datetime import datetime
from typing import List
from pydantic import BaseModel
from eth_typing import BLSPubkey, BLSPrivateKey, BLSSignature
import json

class PublicKeyEntry(BaseModel):
    id: str
    type: str
    publicKeyMultibase: str

class ServiceEntry(BaseModel):
    type: str
    serviceEndpoint: str

class Capabilities(BaseModel):
    supportedModels: List[str]
    maxComputeTime: str
    permissions: List[str]

class PolicyConstraints(BaseModel):
    allowed_interaction_hours: str
    max_data_size: str

class Proof(BaseModel):
    type: str
    created: datetime
    verificationMethod: str
    proofValue: str

class DIDDocument(BaseModel):
    id: str
    publicKey: List[PublicKeyEntry]
    service: List[ServiceEntry]
    capabilities: Capabilities
    policy_constraints: PolicyConstraints
    proof: Proof | None = None

    def to_json(self, *, indent: int | None = None) -> str:
        model_dict = self.model_dump(
            mode='json',
            by_alias=True,
            exclude_none=True
        )
        return json.dumps(model_dict, indent=indent, sort_keys=True)

    @classmethod
    def from_json(cls, data: str) -> "DIDDocument":
        return cls.model_validate_json(data)

class TaskMetadata(BaseModel):
    initiator: str
    participants: List[str]
    description: str
    deadline: int
