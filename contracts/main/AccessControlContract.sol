// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IACC.sol";
import "../lib/TemporalPolicyLogic.sol";
import "../lib/DIDAttributePolicyLogic.sol";
import "../lib/EnvironmentalPolicyLogic.sol";
import "../interfaces/IAGC.sol";
import "../lib/BLS.sol";
import "../lib/BN256G2.sol";

contract AccessControlContract is IACC {
    struct PoliciesEntry {
        Policy[] policies;
        uint8 requiredSigs;
        uint256 nonce;
        bool exists;
    }

    event DebugPayload(bytes calculatedPayload);

    event TokenIssued(
        string agentDID,
        string actionIdentifier,
        string resourceIdentifier,
        uint256 expiry
    );

    uint256[4][5] internal _blsPubKeyList = [
        /* key-1 */
        [
            7201262511018777420451623912981106805074895484287586479273509767667031020877,
            20627995582691274325938795393287500578829791078774336744819305859549221054247,
            17794544309597632664804340361278364484914857652765668401051331223281973265488,
            16428373389911722451866691214395631318837975390055736858258279478012471302068
        ],
        /* key-2 */
        [
            16434898235636967359907296089219646677434070620369214688456265912781365309740,
            20672905215967458025863051617247169375376474967764917936943384557269291631707,
            21082228425857990356657446562831270628394855211199455426641043315157773108500,
            6836206877332651390097084383609590185148303449902042757297653320094804212287
        ],
        /* key-3 */
        [
            9799171705170468065272349835531654635184539585297902249724341319010720592456,
            4583224473756412134598492934991320648693771207254682869740814743783417776115,
            10333586867519003804950951510402253133954594662645400621716312600463417762187,
            3387986602677557717495442587955363899785285107168820325512707677224587602421
        ],
        /* key-4 */
        [
            5159020562597402209428121078249167730088529356255454136598327015868231914806,
            20688083087888160286743136529691971779201342198606331628359833282625656020108,
            19028121209301892988000839473152200147897750033456956113172372269206363401876,
            10424726172542083659009102852390757309048665182873384172664112560956080117768
        ],
        /* key-5 */
        [
            10213554732849998790090689158401969308069776785180793695124967312334345756572,
            20712802657811935955414069141625701711122135244599603342802493798180707315723,
            13363941958492403586700552175411348053136024457768386857160623775844466087194,
            8298407620731997134278584413798174062700966781613970239543932432091190233924
        ]
    ];

    mapping(bytes32 => uint256) private validTokenHashes;
    mapping(bytes32 => PoliciesEntry) private _policies;

    string public systemThreatLevel = "low";

    function getPolicyNonce(
        string calldata resourceIdentifier,
        string calldata actionIdentifier
    ) external view returns (uint256) {
        bytes32 key = _policyKey(resourceIdentifier, actionIdentifier);
        require(_policies[key].exists, "ACC: policy not found");
        return _policies[key].nonce;
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
            require(params.requiredSigs > 0, "ACC: invalid sig threshold");
            entry.requiredSigs = params.requiredSigs;
            entry.exists = true;
            entry.policies.push(newPolicy);
            return true;
        }

        bytes memory payload = abi.encodePacked(
            params.resourceIdentifier,
            params.actionIdentifier,
            params.policyTypeStr,
            keccak256(encodedParams),
            entry.nonce
        );
        uint256[2] memory H = BLS.hashToPoint("ACC", payload);

        uint256[4] memory aggPk;
        uint256 count = 0;
        (aggPk, count) = _aggregate(params.pksMask);
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
            resourceIdentifier: params.resourceIdentifier,
            actionIdentifier: params.actionIdentifier,
            policyTypeStr: params.policyTypeStr,
            paramsHash: paramsHash,
            aggSig: params.aggSig,
            pksMask: params.pksMask
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
    ) internal view returns (bool) {
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

    function evaluate(
        string calldata agentDID,
        string calldata resourceIdentifier,
        string calldata actionIdentifier
    ) external returns (AccessToken memory token) {
        bool isAuthorized = evaluateAccess(agentDID, resourceIdentifier, actionIdentifier);

        require(isAuthorized, "ACC: Unauthorized");

        uint256 expirationTime = block.timestamp + 1 hours;

        token = AccessToken({
            agentDID: agentDID,
            actionIdentifier: actionIdentifier,
            resourceIdentifier: resourceIdentifier,
            expiry: expirationTime
        });

        bytes32 tokenHash = getTokenHash(token);

        validTokenHashes[tokenHash] = token.expiry;

        emit TokenIssued(agentDID, actionIdentifier, resourceIdentifier, token.expiry);

        return token;
    }

    function verifyTokenHash(bytes32 tokenHash) external view returns (bool) {
        uint256 expiry = validTokenHashes[tokenHash];
        return expiry != 0 && expiry >= block.timestamp;
    }

    function getTokenHash(
        AccessToken memory token
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            token.agentDID,
            "|",
            token.actionIdentifier,
            "|",
            token.resourceIdentifier,
            "|",
            token.expiry
        ));
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
        uint8 pksMask;
    }

    function _verifyAggregateSignature(
        VerifySigInternalParams memory sigParams
    ) internal view {
        bytes memory payload = abi.encodePacked(
            sigParams.resourceIdentifier,
            sigParams.actionIdentifier,
            sigParams.policyTypeStr,
            sigParams.paramsHash,
            sigParams.entryRef.nonce
        );
        uint256[2] memory H = BLS.hashToPoint("ACC", payload);

        uint256[4] memory aggPk;
        uint8 count = 0;
        (aggPk, count) = _aggregate(sigParams.pksMask);
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