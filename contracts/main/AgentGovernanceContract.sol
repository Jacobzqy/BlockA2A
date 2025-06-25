// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IAGC.sol";
import "../lib/BLS.sol";
import "../lib/BN256G2.sol";


/**
 * @title  AgentGovernanceContract
 * @notice DID registry with on-chain BLS signature verification.
 * @dev    This version is corrected for testability and logical consistency.
 */
contract AgentGovernanceContract is IAGC {
    // --- STATE VARIABLES ---

    // Oracle public keys are injected via constructor for deterministic testing
    uint256[4][5] internal _blsPubKeyList;

    // Key mappings are public to allow for state verification in tests
    mapping(string => DIDEntry) public _didEntries;
    mapping(string => bool) public _isDIDRegistered;
    mapping(string => uint256) public nonces;


    // --- CONSTANTS AND ENUMS ---

    string public constant DID_PREFIX = "did:blocka2a:";
    uint256 public constant PREFIX_LENGTH = 13;
    uint256 public constant EXPECTED_DID_LENGTH = PREFIX_LENGTH + 10;

    // These constants are now only used to derive the domain strings for hashToPoint
    bytes32 public constant DST_UPDATE = keccak256("AGC-update");
    bytes32 public constant DST_REVOKE = keccak256("AGC-revoke");

    enum DIDLifecycleState {
        Active,
        Revoked
    }

    struct DIDEntry {
        string DID;
        uint256 version;
        bytes32 currentDocumentHash;
        uint256 timestamp;
        DIDLifecycleState currentState;
        string cid;
        uint8 requiredSigsForUpdate;
    }


    // --- CONSTRUCTOR & MODIFIERS ---

    constructor(uint256[4][5] memory initialPubKeys) {
        _blsPubKeyList = initialPubKeys;
    }

    modifier didMustExist(string memory DID) {
        require(_isDIDRegistered[DID], "AGC: DID not registered");
        _;
    }

    modifier didMustBeActive(string memory DID) {
        require(_didEntries[DID].currentState == DIDLifecycleState.Active, "AGC: DID not active");
        _;
    }


    // --- CORE FUNCTIONS ---

    function register(
        string memory DID,
        bytes32 documentHash,
        string memory cid,
        uint8 _requiredSigsForCapUpdate
    ) external override returns (bool success) {
        require(_validDIDFormat(DID), "AGC: Invalid DID format");
        require(!_isDIDRegistered[DID], "AGC: DID already registered");
        require(_requiredSigsForCapUpdate > 0, "AGC: requiredSigsForCapUpdate must be > 0");

        _didEntries[DID] = DIDEntry({
            DID: DID,
            version: 1,
            currentDocumentHash: documentHash,
            timestamp: block.timestamp,
            currentState: DIDLifecycleState.Active,
            cid: cid,
            requiredSigsForUpdate: _requiredSigsForCapUpdate
        });

        _isDIDRegistered[DID] = true;
        nonces[DID] = 1;

        emit DIDCreated(DID, documentHash);
        return true;
    }

    function update(
        string memory DID,
        bytes32 newDocumentHash,
        uint256[2] memory aggSig,
        uint8 pksMask
    ) external override didMustExist(DID) didMustBeActive(DID) returns (bool success) {
        DIDEntry storage entry = _didEntries[DID];

        // 【最终修正】签名负载 (payload) 只包含纯业务数据，不再打包 DST_UPDATE 常量。
        bytes memory payload = abi.encodePacked(
            DID,
            newDocumentHash,
            entry.version
        );

        // 使用字符串 "AGC-update" 作为哈希算法的域，与 Python 库的行为完全匹配。
        uint256[2] memory H = BLS.hashToPoint("AGC-update", payload);

        uint256[4] memory aggPk;
        uint256 signerCount;
        (aggPk, signerCount) = _aggregate(pksMask);

        require(signerCount >= entry.requiredSigsForUpdate, "AGC: not enough signers");

        (bool ok, ) = BLS.verifySingle(aggSig, aggPk, H);
        require(ok, "AGC: aggregate signature verification failed");

        entry.currentDocumentHash = newDocumentHash;
        entry.version++;
        entry.timestamp = block.timestamp;

        emit DIDDocumentUpdated(DID, newDocumentHash);
        return true;
    }

    function revoke(
        string memory DID,
        uint256[2] memory aggSig,
        uint8 pksMask
    ) external override didMustExist(DID) didMustBeActive(DID) returns (bool success) {
        DIDEntry storage entry = _didEntries[DID];

        // 【最终修正】签名负载 (payload) 只包含纯业务数据，不再打包 DST_REVOKE 常量。
        bytes memory payload = abi.encodePacked(
            DID,
            bytes32(0),
            entry.version
        );

        // 使用字符串 "AGC-revoke" 作为哈希算法的域。
        uint256[2] memory H = BLS.hashToPoint("AGC-revoke", payload);

        uint256[4] memory aggPk;
        uint256 signerCount;
        (aggPk, signerCount) = _aggregate(pksMask);
        require(signerCount >= entry.requiredSigsForUpdate, "AGC: not enough signers");

        (bool ok, ) = BLS.verifySingle(aggSig, aggPk, H);
        require(ok, "AGC: aggregate signature verification failed");

        entry.currentState = DIDLifecycleState.Revoked;
        entry.version++;
        entry.timestamp = block.timestamp;

        emit DIDRevoked(DID);
        return true;
    }

    function resolve(
        string memory DID
    ) external override didMustExist(DID) didMustBeActive(DID) view returns (
        bytes32 documentHash,
        string memory cid
    ) {
        DIDEntry storage entry = _didEntries[DID];
        return (entry.currentDocumentHash, entry.cid);
    }


    // --- INTERNAL HELPERS ---

    function _aggregate(uint8 mask)
        internal view returns (uint256[4] memory aggPk, uint256 count)
    {
        for (uint8 i = 0; i < _blsPubKeyList.length; i++) {
            if ((mask & (1 << i)) != 0) {
                (aggPk[0], aggPk[1], aggPk[2], aggPk[3]) = BN256G2.ECTwistAdd(
                    aggPk[0], aggPk[1], aggPk[2], aggPk[3],
                    _blsPubKeyList[i][0], _blsPubKeyList[i][1], _blsPubKeyList[i][2], _blsPubKeyList[i][3]
                );
                count += 1;
            }
        }
        return (aggPk, count);
    }

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