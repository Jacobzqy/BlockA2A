// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IAGC.sol";
import "../lib/BLS.sol";
import "../lib/BN256G2.sol";


/**
 * @title  AgentGovernanceContract
 * @notice DID registry with on-chain BLS signature verification.
 *
 * @dev    Stores oracle public keys as multibase(Base58-btc) strings and
 *         decodes + decompresses them to G2 limbs on demand.
 */
contract AgentGovernanceContract is IAGC {
    /* ------------------------------------------------------------------ */
    /* 1. Hard-coded oracle G2 pub-keys (uint256[4] per key)               */
    /*     Order: [x_r, x_i, y_r, y_i]   ← 适配 BN256G2.ECTwistAdd()      */
    /* ------------------------------------------------------------------ */
    uint256[4][5] internal _blsPubKeyList = [
        /* key-1 */
        [
            155302429429947430454714132412578599823276127034213940665682739,
            285543129034064108325718659544738068065047089268509686447997063,
            278857955273749781401385018621069603968395460012954950189828822,
             90344424755933869749264184148929625706416963653973445719568523
        ],
        /* key-2 */
        [
            155302429429947430454714132412578599823276127034213940665682739,
            285543129034064108325718659544738068065047089268509686447997063,
            278857955273749781401385018621069603968395460012954950189828822,
             90344424755933869749264184148929625706416963653973445719568523
        ],
        /* key-3 */
        [
            155302429429947430454714132412578599823276127034213940665682739,
            285543129034064108325718659544738068065047089268509686447997063,
            278857955273749781401385018621069603968395460012954950189828822,
             90344424755933869749264184148929625706416963653973445719568523
        ],
        /* key-4 */
        [
            155302429429947430454714132412578599823276127034213940665682739,
            285543129034064108325718659544738068065047089268509686447997063,
            278857955273749781401385018621069603968395460012954950189828822,
             90344424755933869749264184148929625706416963653973445719568523
        ],
        /* key-5 */
        [
            155302429429947430454714132412578599823276127034213940665682739,
            285543129034064108325718659544738068065047089268509686447997063,
            278857955273749781401385018621069603968395460012954950189828822,
             90344424755933869749264184148929625706416963653973445719568523
        ]
    ];

    /**
     * @dev Aggregate G2 public keys selected by a bitmask.
     * @param mask Bitmask selecting which keys to include (LSB = key index 0).
     * @return aggPk The aggregated G2 public key (uint256[4] limbs).
     * @return count Number of keys that were aggregated.
     */
    function _aggregate(uint8 mask)
        internal
        view
        returns (uint256[4] memory aggPk, uint256 count)
    {
        for (uint8 i = 0; i < _blsPubKeyList.length; i++) {
            if ((mask & (1 << i)) != 0) {
                (aggPk[0], aggPk[1], aggPk[2], aggPk[3]) = BN256G2.ECTwistAdd(aggPk[0], aggPk[1], aggPk[2], aggPk[3], _blsPubKeyList[i][0], _blsPubKeyList[i][1], _blsPubKeyList[i][2], _blsPubKeyList[i][3]);
                count += 1;
            }
        }
        return (aggPk, count);
    }

    /// @notice Expected DID prefix string.
    string public constant DID_PREFIX = "did:blocka2a:";

    // Domain separation tags for BLS hash-to-curve
    bytes32 public constant DST_UPDATE = keccak256("AGC-update");
    bytes32 public constant DST_REVOKE = keccak256("AGC-revoke");

    /// @notice Length of the prefix in bytes.
    uint256 public constant PREFIX_LENGTH = 10;

    /// @notice Total expected DID length = prefix + 10 hex chars.
    uint256 public constant EXPECTED_DID_LENGTH = PREFIX_LENGTH + 10;

    enum DIDLifecycleState {
        Active,
        Revoked
    }

    /// @notice Defines the data structure for a DID entry stored on-chain.
    /// @dev Contains metadata and state for a registered DID document, including its IPFS CID.
    struct DIDEntry {
        /// @notice The Decentralized Identifier string.
        string DID;

        /// @notice The version number of the DID document.
        uint256 version;

        /// @notice SHA-256 hash of the current DID document JSON.
        bytes32 currentDocumentHash;

        /// @notice UNIX timestamp when the document was registered or last updated.
        uint256 timestamp;

        /// @notice Current lifecycle state of the DID (e.g., Active, Revoked).
        DIDLifecycleState currentState;

        /// @notice IPFS Content Identifier for the DID document.
        string cid;

        /// @notice Number of signatures required to approve future updates.
        uint8 requiredSigsForUpdate;
    }

    mapping(string => DIDEntry) private _didEntries;
    mapping(string => bool) private _isDIDRegistered;
    mapping(string => uint256) public nonces;

    modifier didMustExist(string memory DID) {
        require(_isDIDRegistered[DID], "AGC: DID not registered");
        _;
    }

    modifier didMustBeActive(string memory DID) {
        require(_didEntries[DID].currentState == DIDLifecycleState.Active, "AGC: DID not active");
        _;
    }

    /**
     * @notice Registers a new DID document on-chain and stores its IPFS CID.
     * @dev CID is persisted in the DIDEntry; controllers are managed elsewhere.
     * @param DID The Decentralized Identifier to register.
     * @param documentHash The SHA-256 hash of the DID document JSON.
     * @param cid The IPFS content identifier for the document.
     * @param _requiredSigsForCapUpdate The number of signatures required for future capability updates.
     * @return success Always returns true on success.
     */
    function register(
        string memory DID,
        bytes32 documentHash,
        string memory cid,
        uint8 _requiredSigsForCapUpdate
    ) external override returns (bool success) {
        // Validate DID format
        if (!_validDIDFormat(DID)) {
            return false;
        }

        // Ensure DID is not already registered
        require(!_isDIDRegistered[DID], "AGC: DID already registered");

        // Ensure at least one signature is required for updates
        require(_requiredSigsForCapUpdate > 0, "AGC: requiredSigsForCapUpdate must be > 0");

        // Persist the DID entry, including CID for later retrieval
        _didEntries[DID] = DIDEntry({
            DID: DID,
            version: 1,
            currentDocumentHash: documentHash,
            timestamp: block.timestamp,
            currentState: DIDLifecycleState.Active,
            cid: cid,
            requiredSigsForUpdate: _requiredSigsForCapUpdate
        });

        // Mark DID as registered and initialize nonce
        _isDIDRegistered[DID] = true;
        nonces[DID] = 1;

        // Emit creation event
        emit DIDCreated(DID, documentHash);

        return true;
    }

    /// @notice Updates the DID document after verifying an aggregated BLS signature.
    /// @dev 1) Uses a constant domain tag DST_UPDATE for both payload and hash-to-curve.
    ///      2) Uses entry.version (instead of separate nonce) for replay protection.
    ///      3) Aggregates public keys from a fixed _blsPubKeyList via controllerMask.
    /// @param DID The Decentralized Identifier to update.
    /// @param newDocumentHash The new SHA-256 hash of the DID document JSON.
    /// @param aggSig The aggregated BLS signature over the update payload.
    /// @param pksMask A bitmask selecting which entries in _blsPubKeyList participated.
    /// @return success Always true if the update and signature verification succeed.
    function update(
        string memory DID,
        bytes32 newDocumentHash,
        uint256[2] memory aggSig,
        uint8 pksMask
    ) external override didMustExist(DID) didMustBeActive(DID) returns (bool success) {
        // 1. 读取并准备条目
        DIDEntry storage entry = _didEntries[DID];

        // 2. 构造签名负载：DST_UPDATE || DID || newDocumentHash || entry.version
        bytes memory payload = abi.encodePacked(
            DST_UPDATE,
            DID,
            newDocumentHash,
            entry.version
        );

        // 3. 将 payload 哈希到 G1 曲线点
        uint256[2] memory H = BLS.hashToPoint("AGC-update", payload);

        // 4. 聚合掩码对应的公钥
        uint256[4] memory aggPk;
        uint256 signerCount;
        (aggPk, signerCount) = _aggregate(pksMask);

        require(signerCount >= entry.requiredSigsForUpdate, "AGC: not enough signers");

        // 5. 验证聚合签名
        (bool ok, ) = BLS.verifySingle(aggSig, aggPk, H);
        require(ok, "AGC: aggregate signature verification failed");

        // 6. 更新链上状态
        entry.currentDocumentHash = newDocumentHash;
        entry.version++;
        entry.timestamp = block.timestamp;

        // 7. 发出事件
        emit DIDDocumentUpdated(DID, newDocumentHash);

        return true;
    }

    /// @notice Revokes a DID after verifying an aggregated BLS signature.
    /// @dev Uses a fixed array of five stored BLS public keys; a bitmask selects signers.
    /// @param DID The Decentralized Identifier to revoke.
    /// @param aggSig The aggregated BLS signature over the revoke payload.
    /// @param pksMask A bitmask indicating which public keys (by index) participated.
    /// @return success True if the revocation and verification succeed.
    function revoke(
        string memory DID,
        uint256[2] memory aggSig,
        uint8 pksMask
    ) external override didMustExist(DID) didMustBeActive(DID) returns (bool success) {
        // Fetch the stored DID entry
        DIDEntry storage entry = _didEntries[DID];

        // Prepare the signing payload: domain separator, DID, zero hash placeholder, and version
        bytes memory payload = abi.encodePacked(
            DST_REVOKE,
            DID,
            bytes32(0),
            entry.version
        );
        // Hash the payload to a G1 curve point using domain-separated tag
        uint256[2] memory H = BLS.hashToPoint("AGC-revoke", payload);

        // Aggregate selected public keys based on mask
        uint256[4] memory aggPk;
        uint256 signerCount;
        (aggPk, signerCount) = _aggregate(pksMask);
        require(signerCount >= entry.requiredSigsForUpdate, "AGC: not enough signers");

        // Verify the aggregated signature
        (bool ok, ) = BLS.verifySingle(aggSig, aggPk, H);
        require(ok, "AGC: aggregate signature verification failed");

        // Mark the DID as revoked and update state
        entry.currentState = DIDLifecycleState.Revoked;
        entry.version++;
        entry.timestamp = block.timestamp;

        emit DIDRevoked(DID);
        return true;
    }

    /// @notice Retrieves the current document hash and IPFS CID for a given DID.
    /// @dev Requires that the DID exists and is in an active state.
    /// @param DID The Decentralized Identifier to resolve.
    /// @return documentHash The SHA-256 hash of the DID document.
    /// @return cid The IPFS content identifier associated with the DID document.
    function resolve(
        string memory DID
    ) external override didMustExist(DID) didMustBeActive(DID) view returns (
        bytes32 documentHash,
        string memory cid
    ) {
        DIDEntry storage entry = _didEntries[DID];
        return (entry.currentDocumentHash, entry.cid);
    }

    /// @notice Checks whether a DID string matches the format "did:blocka2a:[10 hex chars]".
    /// @param DID The DID string to validate.
    /// @return valid True if the DID matches the expected format, false otherwise.
    function _validDIDFormat(string memory DID) internal pure returns (bool valid) {
        bytes memory didBytes = bytes(DID);
        bytes memory prefixBytes  = bytes(DID_PREFIX);

        // Check total length matches prefix + 10 hex characters
        if (didBytes.length != EXPECTED_DID_LENGTH) {
            return false;
        }

        // Verify prefix
        for (uint256 i = 0; i < PREFIX_LENGTH; i++) {
            if (didBytes[i] != prefixBytes[i]) {
                return false;
            }
        }

        // Verify each of the 10 characters is a valid hexadecimal digit
        for (uint256 i = PREFIX_LENGTH; i < didBytes.length; i++) {
            bytes1 char = didBytes[i];
            bool isDigit = (char >= bytes1("0") && char <= bytes1("9"));
            bool isLowerHex = (char >= bytes1("a") && char <= bytes1("f"));
            bool isUpperHex = (char >= bytes1("A") && char <= bytes1("F"));
            if (!(isDigit || isLowerHex || isUpperHex)) {
                return false;
            }
        }
        return true;
    }
}