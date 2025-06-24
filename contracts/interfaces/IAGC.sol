// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IAgentGovernanceContract (IAGC)
 * @dev Interface for an Agent Governance Contract.
 *      Manages the lifecycle of Decentralized Identifiers (DIDs),
 *      their associated document hashes, and controller authorization
 *      via BLS multi-signatures.
 */
interface IAGC {
    // --- Events ---

    /**
     * @dev Emitted when a new DID is created.
     * @param DID The Decentralized Identifier (e.g., "did:blocka2a:xxxxx").
     * @param documentHash The initial hash of the DID document.
     */
    event DIDCreated(
        string indexed DID,
        bytes32 indexed documentHash
    );

    /**
     * @dev Emitted when an existing DID's document hash is updated.
     * @param DID The DID whose document was updated.
     * @param newDocumentHash The new hash of the DID document.
     */
    event DIDDocumentUpdated(
        string indexed DID,
        bytes32 indexed newDocumentHash
    );

    /**
     * @dev Emitted when a DID is revoked.
     * @param DID The DID that was revoked.
     */
    event DIDRevoked(
        string indexed DID
    );

    // --- Functions ---

    function register(
        string        memory DID,
        bytes32       documentHash,
        string memory cid,
        uint8         _requiredSigsForCapUpdate
    ) external returns (bool success);

    /**
     * @notice Update the document hash of an existing DID.
     *         Requires a BLS aggregated signature over the update payload
     *         and a bitmask of participating controllers.
     * @param DID The DID to update.
     * @param newDocumentHash The new document hash.
     * @param aggSig A single BLS aggregated signature (G1 point) covering ≥ k controllers.
     * @param pksMask A bitmask where each set bit indicates a controller included in aggSig.
     * @return success True if the update was authorized and applied.
     */
    function update(
        string        memory DID,
        bytes32       newDocumentHash,
        uint256[2]    memory aggSig,
        uint8       pksMask
    ) external returns (bool success);

    /**
     * @notice Revoke an existing DID.
     *         Requires a BLS aggregated signature over the revocation payload
     *         and a bitmask of participating controllers.
     * @param DID The DID to revoke.
     * @param aggSig A BLS aggregated signature authorizing revocation.
     * @param pksMask A bitmask where each set bit indicates a controller included in aggSig.
     * @return success True if the revocation was authorized and applied.
     */
    function revoke(
        string        memory DID,
        uint256[2]    memory aggSig,
        uint8       pksMask
    ) external returns (bool success);

    /**
     * @notice Resolve a DID to its current document hash.
     * @param DID The DID to resolve.
     * @return documentHash The current hash of the DID document.
     */
    function resolve(
        string memory DID
    ) external view returns (bytes32 documentHash, string memory cid);
}
