// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IAGC.sol";
import "../lib/BLS.sol";

contract AgentGovernanceContract is IAGC {

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
        address[] controllers;
        uint8 requiredSigsForUpdate;
    }

    mapping(string => DIDEntry) private _didEntries;
    mapping(string => bool) private _isDIDRegistered;
    mapping(string => uint256) public nonces;
    mapping(address => uint256[4]) private _blsPubKeys;

    string private constant DID_PREFIX = "did:blocka2a:";
    uint private constant DID_PREFIX_LENGTH = 13;
    uint private constant IDENTIFIER_PART_LENGTH = 5;
    uint private constant EXPECTED_DID_LENGTH = DID_PREFIX_LENGTH + IDENTIFIER_PART_LENGTH;

    modifier didMustExist(string memory DID) {
        require(_isDIDRegistered[DID], "AGC: DID not registered");
        _;
    }

    modifier didMustBeActive(string memory DID) {
        require(_didEntries[DID].currentState == DIDLifecycleState.Active, "AGC: DID not active");
        _;
    }

    function register(
        string memory DID,
        bytes32 documentHash,
        address[] memory controllers,
        uint256[4][] memory blsPubKeys,
        uint8 _requiredSigsForCapUpdate
    ) external override returns (bool success) {
        if (!_validDIDFormat(DID)) {
            return false;
        }

        require(controllers.length > 0, "AGC: Controllers list cannot be empty");
        require(_requiredSigsForCapUpdate > 0 && _requiredSigsForCapUpdate <= controllers.length, "AGC: Invalid required signatures count");
        require(!_isDIDRegistered[DID], "AGC: DID already registered");
        require(blsPubKeys.length == controllers.length, "AGC: pubkey length mismatch");

        for(uint256 i = 0; i < controllers.length; i++) {
            _blsPubKeys[controllers[i]] = blsPubKeys[i];
        }

        _didEntries[DID] = DIDEntry({
            DID: DID,
            version: 1,
            currentDocumentHash: documentHash,
            timestamp: block.timestamp,
            currentState: DIDLifecycleState.Active,
            controllers: controllers,
            requiredSigsForUpdate: _requiredSigsForCapUpdate
        });

        _isDIDRegistered[DID] = true;
        nonces[DID] = 1;

        emit DIDCreated(DID, documentHash, controllers);

        return true;
    }

    function update(
        string memory DID,
        bytes32 newDocumentHash,
        uint256[2] memory aggSig,
        uint256 controllerMask
    ) external override didMustExist(DID) didMustBeActive(DID) returns (bool success) {
        DIDEntry storage entry = _didEntries[DID];

        bytes memory payload = abi.encodePacked(
            keccak256(bytes("AGC")),
            DID,
            newDocumentHash,
            nonces[DID]
        );
        uint256[2] memory H = BLS.hashToPoint("AGC", payload);

        uint256[4] memory aggPk;
        uint256 count = 0;
        for(uint256 i = 0; i < entry.controllers.length; i++) {
            if ((controllerMask >> i) & 1 == 1) {
                aggPk = BLS.g2Add(aggPk, _blsPubKeys[entry.controllers[i]]);
                count++;
            }
        }
        require(count >= entry.requiredSigsForUpdate, "AGC: not enough signers");

        (bool ok, ) = BLS.verifySingle(aggSig, aggPk, H);
        require(ok, "AGC: agg-sig verify fail");

        entry.currentDocumentHash = newDocumentHash;
        entry.version++;
        entry.timestamp = block.timestamp;
        nonces[DID]++;

        emit DIDDocumentUpdated(DID, newDocumentHash);
        return true;
    }

    function revoke(
        string memory DID,
        uint256[2] memory aggSig,
        uint256 controllerMask
    ) external override didMustExist(DID) didMustBeActive(DID) returns (bool success) {
        DIDEntry storage entry = _didEntries[DID];
        bytes memory payload = abi.encodePacked(
            keccak256(bytes("AGC")),
            DID,
            bytes32(0),
            nonces[DID]
        );
        uint256[2] memory H = BLS.hashToPoint("AGC", payload);

        uint256[4] memory aggPk;
        uint256 count = 0;
        for(uint256 i = 0; i < entry.controllers.length; i++) {
            if ((controllerMask >> i) & 1 == 1) {
                aggPk = BLS.g2Add(aggPk, _blsPubKeys[entry.controllers[i]]);
                count++;
            }
        }
        require(count >= entry.requiredSigsForUpdate, "AGC: not enough signers");

        (bool ok, ) = BLS.verifySingle(aggSig, aggPk, H);
        require(ok, "AGC: agg-sig verify fail");

        _didEntries[DID].currentState = DIDLifecycleState.Revoked;
        _didEntries[DID].timestamp = uint64(block.timestamp);
        _didEntries[DID].version++;
        nonces[DID]++;

        emit DIDRevoked(DID);
        return true;
    }

    function resolve(
        string memory DID
    ) external override didMustExist(DID) didMustBeActive(DID) view returns (bytes32 documentHash) {
        return _didEntries[DID].currentDocumentHash;
    }

    function _validDIDFormat(string memory DID) internal pure returns (bool) {
        bytes memory didBytes = bytes(DID);

        if(didBytes.length != EXPECTED_DID_LENGTH) {
            return false;
        }

        bytes memory prefixBytes = bytes(DID_PREFIX);
        for (uint i = 0; i < DID_PREFIX_LENGTH; i++) {
            if (didBytes[i] != prefixBytes[i]) {
                return false;
            }
        }

        for (uint i = DID_PREFIX_LENGTH; i < EXPECTED_DID_LENGTH; i++) {
            bytes1 char = didBytes[i];
            if (!((char >= bytes1(uint8(bytes1('0'))) && char <= bytes1(uint8(bytes1('9')))) ||
                  (char >= bytes1(uint8(bytes1('a'))) && char <= bytes1(uint8(bytes1('f')))) ||
                  (char >= bytes1(uint8(bytes1('A'))) && char <= bytes1(uint8(bytes1('F')))))) {
                return false;
            }
        }
        return true;
    }
}