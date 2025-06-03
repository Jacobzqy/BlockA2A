// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IACC {
    enum PolicyType {TEMPORAL, DIDATTRIBUTE, ENVIRONMENTAL}

    enum ActionType {READ, MODIFY, INVOKE, DELETE}

    struct Policy {
        PolicyType policyType;
        bytes policyParameters;
    }

    struct KV {
        string key;
        string value;
    }

    struct RegisterPolicyParams {
        string resourceIdentifier;
        string actionIdentifier;
        string policyTypeStr;
        KV[] policyParameters;
        address[] controllers;
        uint256[4][] blsPubKeys;
        uint8 requiredSigs;
        uint256[2] aggSig;
        uint256 controllerMask;
    }

    struct RemovePolicyParams {
        string resourceIdentifier;
        string actionIdentifier;
        string policyTypeStr;
        KV[] policyParameters;
        uint256[2] aggSig;
        uint256 controllerMask;
    }

    function getPolicy(
        string calldata resourceIdentifier,
        string calldata actionIdentifier
    ) external view returns (Policy[] memory);

    function registerPolicy(
        RegisterPolicyParams calldata params
    ) external returns (bool);

    function removePolicy(
        RemovePolicyParams calldata params
    ) external returns (bool);

    function evaluateAccess(
        string calldata agentDID,
        string calldata resourceIdentifier,
        string calldata actionIdentifier
    ) external returns (bool);
}