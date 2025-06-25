// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../lib/BLS.sol";
import "../lib/BN256G2.sol";

contract InteractionLogicContract {
    enum State {OrderCreated, ProductionScheduled, Shipped}
    State private currentState;

    enum WorkflowEvent {PaymentReceived, ManufacturingComplete}

    uint256[4][5] private _blsPubKeyList;
    uint8 private requiredSigs;
    uint256 private nonce;
    uint256 private lastTransitionTime;


    struct TransitionRule {
        State from;
        State to;
        WorkflowEvent trigger;
        uint256 deadline;
    }
    TransitionRule[2] private _rules;

    event TransitionExecuted(State indexed from, WorkflowEvent indexed eventId, State indexed to, uint256 timestamp);

    constructor(
        uint256[4][5] memory _blsPks,
        uint8 _k
    ) {
        _blsPubKeyList = _blsPks;
        requiredSigs = _k;
        currentState = State.OrderCreated;
        lastTransitionTime = block.timestamp;

        _rules[0] = TransitionRule({
            from: State.OrderCreated,
            trigger: WorkflowEvent.PaymentReceived,
            to:   State.ProductionScheduled,
            deadline: 0
        });
        _rules[1] = TransitionRule({
            from: State.ProductionScheduled,
            trigger: WorkflowEvent.ManufacturingComplete,
            to:   State.Shipped,
            deadline: 72 hours
        });
    }

    function transition(
        WorkflowEvent eventId,
        uint256[2] calldata aggSig,
        uint8 pksMask
    ) external returns(bool) {
        TransitionRule memory rule = _matchRule(currentState, eventId);
        if (rule.deadline > 0) {
            require(block.timestamp <= lastTransitionTime + rule.deadline, "ILC: deadline passed");
        }
        _checkMultisig(eventId, aggSig, pksMask);

        State prev = currentState;
        currentState = rule.to;
        nonce++;

        emit TransitionExecuted(prev, eventId, currentState, block.timestamp);
        return true;
    }

    function _matchRule(
        State s,
        WorkflowEvent e
    ) internal view returns (TransitionRule memory) {
        for (uint8 i; i < _rules.length; ++i) {
            if (_rules[i].from == s && _rules[i].trigger == e){
                return _rules[i];
            }
        }
        revert("ILC: invalid transition");
    }

    function _aggregate(uint8 mask)
        internal
        view
        returns (uint256[4] memory aggPk, uint8 count)
    {
        for (uint8 i = 0; i < _blsPubKeyList.length; i++) {
            if ((mask & (1 << i)) != 0) {
                (aggPk[0], aggPk[1], aggPk[2], aggPk[3]) = BN256G2.ECTwistAdd(aggPk[0], aggPk[1], aggPk[2], aggPk[3], _blsPubKeyList[i][0], _blsPubKeyList[i][1], _blsPubKeyList[i][2], _blsPubKeyList[i][3]);
                count += 1;
            }
        }
        return (aggPk, count);
    }

    function _checkMultisig(
        WorkflowEvent e,
        uint256[2] calldata aggSig,
        uint8 pksMask
    ) internal view {
        bytes memory payload = abi.encodePacked(
            uint8(currentState),
            uint8(e),
            nonce
        );
        uint256[2] memory H = BLS.hashToPoint("ILC", payload);

        uint256[4] memory aggPk;
        uint8 count = 0;
        (aggPk, count) = _aggregate(pksMask);

        require(count >= requiredSigs, "ILC: sig quorum fail");

        (bool ok, ) = BLS.verifySingle(aggSig, aggPk, H);
        require(ok, "ILC: sig verify fail");
    }
}