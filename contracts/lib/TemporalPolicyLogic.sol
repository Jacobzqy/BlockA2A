// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library TemporalPolicyLogic {
    struct TemporalParams {
        uint256 validAfter;
        uint256 validBefore;
        uint32 dailyStart;
        uint32 dailyEnd;
    }

    function evaluate(TemporalParams calldata params) external view returns (bool granted) {
        uint256 nowTs = block.timestamp;

        if(nowTs < params.validAfter || nowTs > params.validBefore) {
            return false;
        }

        if(params.dailyEnd > params.dailyStart) {
            uint256 secsSinceMid = nowTs % 86400;
            if(secsSinceMid < params.dailyStart || secsSinceMid > params.dailyEnd) {
                return false;
            }
        }

        return true;
    }
}