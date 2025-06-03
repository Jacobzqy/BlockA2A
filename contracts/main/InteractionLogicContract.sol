// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../lib/BLS.sol";

contract InteractionLogicContract {
    enum State {OrderCreated, ProductionScheduled, Shipped}
    State private currentState;

    enum WorkflowEvent {PaymentReceived, ManufacturingComplete}

    address[] private controllers;
    uint256[4][] private blsPubKeys;
    uint8 private requiredSigs;
    uint256 private nonce;

    struct TransitionRule {
        State from;
        State to;
        WorkflowEvent trigger;
        uint256 deadline;
    }
    TransitionRule[2] private _rules;

    event TransitionExecuted(State indexed from, WorkflowEvent indexed eventId, State indexed to, uint256 timestamp);

    constructor(
        address[] memory _ctrls,
        uint256[4][] memory _blsPks,
        uint8 _k
    ) {
        require(_ctrls.length == _blsPks.length && _k > 0 && _k <= _ctrls.length, "ILC: bad controller set");
        controllers = _ctrls;
        blsPubKeys = _blsPks;
        requiredSigs = _k;
        currentState = State.OrderCreated;

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
        uint256 ctrlMask
    ) external returns(bool) {
        TransitionRule memory rule = _matchRule(State.OrderCreated, eventId);
        require(block.timestamp <= rule.deadline + block.timestamp, "ILC: deadline passed");
        _checkMultisig(eventId, aggSig, ctrlMask);

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

    function _checkMultisig(
        WorkflowEvent e,
        uint256[2] calldata aggSig,
        uint256 mask
    ) internal view {
        bytes memory payload = abi.encodePacked(
            keccak256(bytes("ILC")),
            uint8(currentState),
            uint8(e),
            nonce
        );
        uint256[2] memory H = BLS.hashToPoint("ILC", payload);

        uint256[4] memory aggPk;
        uint256 count = 0;
        for (uint256 i = 0; i < controllers.length; ++i) {
            if ((mask >> i) & 1 == 1) {
                aggPk = BLS.g2Add(aggPk, blsPubKeys[i]);
                count++;
            }
        }
        require(count >= requiredSigs, "ILC: sig quorum fail");

        (bool ok, ) = BLS.verifySingle(aggSig, aggPk, H);
        require(ok, "ILC: sig verify fail");
    }
}