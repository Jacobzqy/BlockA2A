// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IACC.sol";
import "../lib/TemporalPolicyLogic.sol";
import "../lib/DIDAttributePolicyLogic.sol";
import "../lib/EnvironmentalPolicyLogic.sol";
import "../interfaces/IAGC.sol";
import "../lib/BLS.sol";

contract AccessControlContract is IACC {
    struct PoliciesEntry {
        Policy[] policies;
        address[] controllers;
        uint256[4][] blsPubKeys;
        uint8 requiredSigs;
        uint256 nonce;
        bool exists;
    }

    mapping(bytes32 => PoliciesEntry) private _policies;

    string public systemThreatLevel = "low";

    function getPolicy(
        string calldata resourceIdentifier,
        string calldata actionIdentifier
    ) external view override returns (Policy[] memory) {
        bytes32 key = _policyKey(resourceIdentifier, actionIdentifier);
        if(_policies[key].exists) return _policies[key].policies;
        revert("ACC: policy not found");
    }

    function registerPolicy(
        RegisterPolicyParams calldata params
    ) external returns (bool) {
        bytes32 key = _policyKey(params.resourceIdentifier, params.actionIdentifier);
        PoliciesEntry storage entry = _policies[key];

        PolicyType pType = _strToPolicyType(params.policyTypeStr);
        bytes memory encodedParams = abi.encode(params.policyParameters);
        Policy memory newPolicy = Policy({policyType: pType, policyParameters: encodedParams});

        if(!entry.exists) {
            require(params.controllers.length > 0, "ACC: empty controllers");
            require(params.controllers.length == params.blsPubKeys.length, "ACC: ctrl/pubkey length mismatch");
            require(params.requiredSigs > 0 && params.requiredSigs <= params.controllers.length, "ACC: invalid sig threshold");

            entry.controllers = params.controllers;
            entry.blsPubKeys = params.blsPubKeys;
            entry.requiredSigs = params.requiredSigs;
            entry.exists = true;

            entry.policies.push(newPolicy);
            return true;
        }

        bytes memory payload = abi.encodePacked(
            keccak256(bytes("ACC")),
            params.resourceIdentifier,
            params.actionIdentifier,
            params.policyTypeStr,
            keccak256(encodedParams),
            entry.nonce
        );
        uint256[2] memory H = BLS.hashToPoint("ACC", payload);

        uint256[4] memory aggPk;
        uint256 count = 0;
        for(uint256 i = 0; i < entry.controllers.length; i++) {
            if((params.controllerMask >> i) & 1 == 1) {
                aggPk = BLS.g2Add(aggPk, entry.blsPubKeys[i]);
                count++;
            }
        }
        require(count >= entry.requiredSigs, "ACC: not enough signers");

        (bool ok, ) = BLS.verifySingle(params.aggSig, aggPk, H);
        require(ok, "ACC: agg-sig verify failed");

        entry.policies.push(newPolicy);
        return true;
    }

    function removePolicy(
        RemovePolicyParams calldata params
    ) external returns (bool) {
        bytes32 key = _policyKey(params.resourceIdentifier, params.actionIdentifier);
        PoliciesEntry storage entry = _policies[key];
        require(entry.exists, "ACC: policy-set not found");

        bytes32 paramsHash = keccak256(abi.encode(params.policyParameters));

        PolicyType pType = _strToPolicyType(params.policyTypeStr);
        uint256 idx = _findPolicyIndex(entry, pType, paramsHash);

        VerifySigInternalParams memory verifyInternalCallParams = VerifySigInternalParams({
            entryRef: entry,
            resourceIdentifier: params.resourceIdentifier, // 或直接的 resourceIdentifier 变量
            actionIdentifier: params.actionIdentifier,   // 或直接的 actionIdentifier 变量
            policyTypeStr: params.policyTypeStr,       // 或直接的 policyTypeStr 变量
            paramsHash: paramsHash,                    // 局部变量 paramsHash
            aggSig: params.aggSig,                     // 或直接的 aggSig 变量
            controllerMask: params.controllerMask      // 或直接的 controllerMask 变量
        });

        _verifyAggregateSignature(
            verifyInternalCallParams
        );

        _removePolicyAt(entry, idx, key);
        return true;
    }

    function evaluateAccess(
        string calldata agentDID,
        string calldata resourceIdentifier,
        string calldata actionIdentifier
    ) external view returns (bool) {
        bytes32 key = _policyKey(resourceIdentifier, actionIdentifier);
        PoliciesEntry storage entry = _policies[key];
        if(!entry.exists) return true;

        for(uint256 i = 0; i < entry.policies.length; i++) {
            Policy storage p = entry.policies[i];

            if(p.policyType == PolicyType.TEMPORAL) {
                TemporalPolicyLogic.TemporalParams memory tp = abi.decode(p.policyParameters, (TemporalPolicyLogic.TemporalParams));
                bool ok = TemporalPolicyLogic.evaluate(tp);
                if(!ok) return false;
            } else if(p.policyType == PolicyType.DIDATTRIBUTE) {
                if (keccak256(bytes(agentDID)) == 0) return false;
            } else if(p.policyType == PolicyType.ENVIRONMENTAL) {
                EnvironmentalPolicyLogic.RiskLevel ep = abi.decode(p.policyParameters, (EnvironmentalPolicyLogic.RiskLevel));
                bool ok = EnvironmentalPolicyLogic.evaluate(systemThreatLevel, ep);
                if(!ok) return false;
            } else {
                revert("ACC: unknown policy type");
            }
        }
        return true;
    }

    function _policyKey(
        string calldata resourceIdentifier,
        string calldata actionIdentifier
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(resourceIdentifier, "|", actionIdentifier));
    }

    function _strToPolicyType(string calldata s) internal pure returns (PolicyType) {
        bytes32 h = keccak256(bytes(s));
        if(h == keccak256("TEMPORAL")) return PolicyType.TEMPORAL;
        if(h == keccak256("DIDATTRIBUTE")) return PolicyType.DIDATTRIBUTE;
        if(h == keccak256("ENVIRONMENTAL")) return PolicyType.ENVIRONMENTAL;
        revert("ACC: unknown policy type");
    }

    struct VerifySigInternalParams {
        PoliciesEntry entryRef; // 或者只包含需要的 entry 字段
        string resourceIdentifier;      // calldata 引用
        string actionIdentifier;      // calldata 引用
        string policyTypeStr;         // calldata 引用
        bytes32 paramsHash;
        uint256[2] aggSig;       // memory 引用
        uint256 controllerMask;
    }

    function _verifyAggregateSignature(
        VerifySigInternalParams memory sigParams
    ) internal view {
        bytes memory payload = abi.encodePacked(
            keccak256(bytes("ACC")),
            sigParams.resourceIdentifier,
            sigParams.actionIdentifier,
            sigParams.policyTypeStr,
            sigParams.paramsHash,
            sigParams.entryRef.nonce
        );
        uint256[2] memory H = BLS.hashToPoint("ACC", payload);

        uint256[4] memory aggPk;
        uint256 count = 0;
        for(uint256 i = 0; i < sigParams.entryRef.controllers.length; i++) {
            if((sigParams.controllerMask >> i) & 1 == 1) {
                aggPk = BLS.g2Add(aggPk, sigParams.entryRef.blsPubKeys[i]);
                count++;
            }
        }
        require(count >= sigParams.entryRef.requiredSigs, "ACC: not enough signers");

        (bool ok, ) = BLS.verifySingle(sigParams.aggSig, aggPk, H);
        require(ok, "ACC: agg-sig verify failed");
    }

    function _findPolicyIndex(
        PoliciesEntry storage entry,
        PolicyType pType,
        bytes32 paramsHash
    ) internal view returns (uint256) {
        for (uint256 i = 0; i < entry.policies.length; i++) {
            Policy storage p = entry.policies[i];
            if (
                p.policyType == pType &&
                keccak256(p.policyParameters) == paramsHash
            ) {
                return i;
            }
        }
        revert("ACC: policy not found");
    }

    function _removePolicyAt(
        PoliciesEntry storage entry,
        uint256 idx,
        bytes32 key
    ) internal {
        uint256 last = entry.policies.length - 1;
        if (idx != last) {
            entry.policies[idx] = entry.policies[last];
        }
        entry.policies.pop();
        entry.nonce += 1;

        if (entry.policies.length == 0) {
            delete _policies[key];
        }
    }
}