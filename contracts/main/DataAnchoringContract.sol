// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../lib/BLS.sol";

/// @title Data Anchoring Contract with BLS Threshold Updates
/// @notice Anchors off-chain data to IPFS, then allows status updates
///         only when a valid BLS threshold signature is provided.
/// @dev    BLS public keys are hardcoded at deployment; update uses all keys.
contract DataAnchoringContract {
    using BLS for *;

    /// @dev Anchor record structure
    struct Record {
        bytes32 dataHash;  // SHA-256 digest
        string  cid;       // IPFS CID
        uint256 expiry;    // Expiration timestamp
        string  status;    // Status string
    }

    /// @notice Hardcoded BLS G2 public keys (uint256[4] points)
    uint256[4][] public blsPubKeys;

    /// @dev Mapping from dataHash to its Record
    mapping(bytes32 => Record) private records;

    /// @notice Emitted when data is first anchored
    event DataAnchored(
        bytes32 indexed dataHash,
        string    cid,
        uint256   expiry,
        string    status
    );

    /// @notice Emitted when an anchor record is updated
    event DataUpdated(
        bytes32 indexed dataHash,
        string    newStatus
    );

    /// @dev Example BLS public keys (replace with real keys in production)
    constructor() {
        // These are placeholder values; in real usage, deployer should
        // supply actual G2 public keys for the BLS threshold scheme.
        blsPubKeys.push([0x1, 0x0, 0x2, 0x0]);
        blsPubKeys.push([0x3, 0x0, 0x4, 0x0]);
        blsPubKeys.push([0x5, 0x0, 0x6, 0x0]);
    }

    /// @notice Anchor new data on-chain
    /// @param dataHash SHA-256 hash of the data
    /// @param cid IPFS CID where the data is stored
    /// @param expiry Expiration timestamp for this anchor
    /// @param status Initial status label
    function anchor(
        bytes32 dataHash,
        string calldata cid,
        uint256 expiry,
        string calldata status
    ) external {
        require(dataHash != bytes32(0), "DAC: zero dataHash");
        require(bytes(cid).length > 0,    "DAC: empty CID");
        require(expiry > block.timestamp, "DAC: expiry must be future");

        Record storage rec = records[dataHash];
        require(rec.dataHash == bytes32(0), "DAC: already anchored");

        rec.dataHash = dataHash;
        rec.cid      = cid;
        rec.expiry   = expiry;
        rec.status   = status;

        emit DataAnchored(dataHash, cid, expiry, status);
    }

    /// @notice Update the status of an existing anchor using BLS signature
    /// @param aggSig BLS aggregate signature over `dataHash|milestone`
    /// @param dataHash SHA-256 hash key of the record
    /// @param milestone Milestone identifier string (e.g. "milestone-1")
    /// @param dids List of DIDs whose keys participated in the aggregate signature
    function update(
        uint256[2] calldata aggSig,
        bytes32 dataHash,
        string calldata milestone,
        string[] calldata dids
    ) external {
        Record storage rec = records[dataHash];
        require(rec.dataHash != bytes32(0), "DAC: not anchored");

        // Build message = keccak256(dataHash || "|" || milestone)
        bytes memory payload = abi.encodePacked(
            dataHash,
            bytes("|"),
            bytes(milestone)
        );
        uint256[2] memory H = BLS.hashToPoint("DAC", payload);

        // Aggregate all hardcoded public keys
        uint256[4] memory aggPk;
        for (uint i = 0; i < blsPubKeys.length; i++) {
            aggPk = BLS.g2Add(aggPk, blsPubKeys[i]);
        }

        // Verify the aggregate signature against message H
        (bool ok, ) = BLS.verifySingle(aggSig, aggPk, H);
        require(ok, "DAC: BLS verify failed");

        // Update status
        string memory newStatus = string(abi.encodePacked(milestone, "_verified"));
        rec.status = newStatus;

        emit DataUpdated(dataHash, newStatus);
    }

    /// @notice Retrieve the anchor record for a given dataHash
    /// @param dataHash SHA-256 hash key
    /// @return dataHash_ The stored data hash
    /// @return cid_ The IPFS CID
    /// @return expiry_ The expiration timestamp
    /// @return status_ The current status string
    function get(bytes32 dataHash)
        external
        view
        returns (
            bytes32 dataHash_,
            string memory cid_,
            uint256 expiry_,
            string memory status_
        )
    {
        Record storage rec = records[dataHash];
        require(rec.dataHash != bytes32(0), "DAC: not anchored");
        return (rec.dataHash, rec.cid, rec.expiry, rec.status);
    }
}
