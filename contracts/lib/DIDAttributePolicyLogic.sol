// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library DIDAttributePolicyLogic {
    struct AttributeRequirement {
        string attributeName;
        string expectedValue;
    }

    struct Attribute {
        string name;
        string[] values;
    }

    function evaluate(
        Attribute[] calldata context,
        AttributeRequirement calldata requirement
    ) external pure returns (bool granted) {
        for(uint256 i = 0; i < context.length; i++) {
            if(keccak256(bytes(context[i].name)) == keccak256(bytes(requirement.attributeName))) {
                string[] calldata vals = context[i].values;
                for(uint256 j = 0; j < vals.length; j++) {
                    if(keccak256(bytes(vals[j])) == keccak256(bytes(requirement.expectedValue))) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}