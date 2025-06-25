// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../lib/BLS.sol";
import "../lib/BN256G2.sol";

/// @title Data Anchoring Contract with BLS Threshold Updates
/// @notice Anchors off-chain data to IPFS, then allows status updates
///         only when a valid BLS threshold signature is provided.
/// @dev    BLS public keys are hardcoded at deployment; update uses all keys.
contract DataAnchoringContract {
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

    /// @dev Anchor record structure
    struct Record {
        bytes32 dataHash;  // SHA-256 digest
        string  cid;       // IPFS CID
        uint256 expiry;    // Expiration timestamp
        string  status;    // Status string
    }

    /// @dev Mapping from dataHash to its Record
    mapping(bytes32 => Record) private records;

    /// @notice Emitted when data is first anchored
    event DataAnchored(
        bytes32   dataHash,
        string    cid,
        uint256   expiry,
        string    status
    );

    /// @notice Emitted when an anchor record is updated
    event DataUpdated(
        bytes32   dataHash,
        string    newStatus
    );

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

    /// @notice Anchor new data on-chain
    /// @param dataHash SHA-256 hash of the data
    /// @param cid IPFS CID where the data is stored
    /// @param expiry Expiration timestamp for this anchor
    /// @param status Initial status label
    function anchor(
        bytes32 dataHash,
        string calldata cid,
        uint256 expiry,
        string calldata status
    ) external {
        require(dataHash != bytes32(0), "DAC: zero dataHash");
        require(bytes(cid).length > 0,    "DAC: empty CID");
        require(expiry > block.timestamp, "DAC: expiry must be future");

        Record storage rec = records[dataHash];
        require(rec.dataHash == bytes32(0), "DAC: already anchored");

        rec.dataHash = dataHash;
        rec.cid      = cid;
        rec.expiry   = expiry;
        rec.status   = status;

        emit DataAnchored(dataHash, cid, expiry, status);
    }

    /// @notice Update the status of an existing anchor using BLS signature
    /// @param aggSig BLS aggregate signature over `dataHash|milestone`
    /// @param dataHash SHA-256 hash key of the record
    /// @param milestone Milestone identifier string (e.g. "milestone-1")
    /// @param dids List of DIDs whose keys participated in the aggregate signature
    function update(
        uint256[2] calldata aggSig,
        bytes32 dataHash,
        string calldata milestone,
        string[] calldata dids,
        uint8 pksMask
    ) external {
        Record storage rec = records[dataHash];
        require(rec.dataHash != bytes32(0), "DAC: not anchored");

        // Build message = keccak256(dataHash || "|" || milestone)
        bytes memory payload = abi.encodePacked(
            dataHash,
            bytes("|"),
            bytes(milestone)
        );
        uint256[2] memory H = BLS.hashToPoint("DAC", payload);

        // Aggregate all hardcoded public keys
        uint256[4] memory aggPk;
        uint8 count;
        (aggPk, count) = _aggregate(pksMask);
        // Verify the aggregate signature against message H
        (bool ok, ) = BLS.verifySingle(aggSig, aggPk, H);
        require(ok, "DAC: BLS verify failed");

        // Update status
        string memory newStatus = string(abi.encodePacked(milestone, "_verified"));
        rec.status = newStatus;

        emit DataUpdated(dataHash, newStatus);
    }

    /// @notice Retrieve the anchor record for a given dataHash
    /// @param dataHash SHA-256 hash key
    /// @return dataHash_ The stored data hash
    /// @return cid_ The IPFS CID
    /// @return expiry_ The expiration timestamp
    /// @return status_ The current status string
    function get(bytes32 dataHash)
        external
        view
        returns (
            bytes32 dataHash_,
            string memory cid_,
            uint256 expiry_,
            string memory status_
        )
    {
        Record storage rec = records[dataHash];
        require(rec.dataHash != bytes32(0), "DAC: not anchored");
        return (rec.dataHash, rec.cid, rec.expiry, rec.status);
    }
}
