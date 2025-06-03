// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library EnvironmentalPolicyLogic {
    enum RiskLevel {LOW, MEDIUM, HIGH}

    function evaluate(
        string calldata contextLevel,
        RiskLevel thresholdLevel
    ) external pure returns (bool granted) {
        uint8 ctx = uint8(_parseLevel(contextLevel));
        uint8 thr = uint8(thresholdLevel);
        return ctx <= thr;
    }

    function _parseLevel(string memory S) internal pure returns (RiskLevel) {
        bytes32 h = keccak256(bytes(S));
        if(h == keccak256(bytes("low"))) {
            return RiskLevel.LOW;
        } else if(h == keccak256(bytes("medium"))) {
            return RiskLevel.MEDIUM;
        } else if(h == keccak256(bytes("high"))) {
            return RiskLevel.HIGH;
        }
        revert("EnvironmentalPolicyLogic: invalid risk level");
    }
}