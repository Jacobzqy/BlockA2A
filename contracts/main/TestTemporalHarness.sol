// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// 导入您要测试的库
import "../lib/TemporalPolicyLogic.sol";

// 这是一个简单的包装合约，专门用于测试库的功能
contract TestTemporalHarness {
    // 定义一个公共函数，它的参数和返回类型与库函数完全相同
    function testEvaluate(
        TemporalPolicyLogic.TemporalParams calldata params
    ) external view returns (bool) {
        // 直接调用库函数并返回其结果
        return TemporalPolicyLogic.evaluate(params);
    }
}