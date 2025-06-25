# Architecture Overview

This page provides an overview of the BlockA2A layered protocol architecture, introducing the responsibilities and interactions of each on-chain and off-chain module.

---

## 1. Layered Protocol Architecture

```mermaid
flowchart TD
    C[Client SDK<br/>(Python/JS)] -->|DID Register/Update| AGC[Agent Governance Layer<br/>AgentGovernanceContract]
    C -->|Data Anchoring| DAC[Data Anchoring Layer<br/>DataAnchoringContract]
    C -->|Task State Change| ILC[State Transition Layer<br/>InteractionLogicContract]
    AGC -->|Store CID/Hash| IPFS[(IPFS)]
    DAC --> IPFS
    ILC -->|BLS Verification| BLS[/BLS Precompile or Library/]
