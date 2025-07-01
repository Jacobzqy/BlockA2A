// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../lib/EnvironmentalPolicyLogic.sol";

/// @title 测试 EnvironmentalPolicyLogic 的包装合约
contract TestEnvironmentalHarness {
    /// @notice 调用库函数并返回结果
    function testEvaluate(
        string calldata contextLevel,
        EnvironmentalPolicyLogic.RiskLevel thresholdLevel
    ) external pure returns (bool) {
        return EnvironmentalPolicyLogic.evaluate(contextLevel, thresholdLevel);
    }
}
