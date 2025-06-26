const { ethers } = require("hardhat");

async function main() {
  const _blsPubKeyList = [
        /* key-1 */
        [
            "7201262511018777420451623912981106805074895484287586479273509767667031020877",
            "20627995582691274325938795393287500578829791078774336744819305859549221054247",
            "17794544309597632664804340361278364484914857652765668401051331223281973265488",
            "16428373389911722451866691214395631318837975390055736858258279478012471302068"
        ],
        /* key-2 */
        [
            "16434898235636967359907296089219646677434070620369214688456265912781365309740",
            "20672905215967458025863051617247169375376474967764917936943384557269291631707",
            "21082228425857990356657446562831270628394855211199455426641043315157773108500",
            "6836206877332651390097084383609590185148303449902042757297653320094804212287"
        ],
        /* key-3 */
        [
            "9799171705170468065272349835531654635184539585297902249724341319010720592456",
            "4583224473756412134598492934991320648693771207254682869740814743783417776115",
            "10333586867519003804950951510402253133954594662645400621716312600463417762187",
            "3387986602677557717495442587955363899785285107168820325512707677224587602421"
        ],
        /* key-4 */
        [
            "5159020562597402209428121078249167730088529356255454136598327015868231914806",
            "20688083087888160286743136529691971779201342198606331628359833282625656020108",
            "19028121209301892988000839473152200147897750033456956113172372269206363401876",
            "10424726172542083659009102852390757309048665182873384172664112560956080117768"
        ],
        /* key-5 */
        [
            "10213554732849998790090689158401969308069776785180793695124967312334345756572",
            "20712802657811935955414069141625701711122135244599603342802493798180707315723",
            "13363941958492403586700552175411348053136024457768386857160623775844466087194",
            "8298407620731997134278584413798174062700966781613970239543932432091190233924"
        ]
    ];

  console.log("Deploying dependent libraries first...");

  // 第一步：分别部署每一个依赖的库

  // 1. 部署 EnvironmentalPolicyLogic 库
  const EnvironmentalPolicyLogicFactory = await hre.ethers.getContractFactory("EnvironmentalPolicyLogic");
  const environmentalPolicyLogic = await EnvironmentalPolicyLogicFactory.deploy();
  await environmentalPolicyLogic.deployed();
  console.log(`-> EnvironmentalPolicyLogic library deployed to: ${environmentalPolicyLogic.address}`);

  // 2. 部署 TemporalPolicyLogic 库
  const TemporalPolicyLogicFactory = await hre.ethers.getContractFactory("TemporalPolicyLogic");
  const temporalPolicyLogic = await TemporalPolicyLogicFactory.deploy();
  await temporalPolicyLogic.deployed();
  console.log(`-> TemporalPolicyLogic library deployed to: ${temporalPolicyLogic.address}`);

  console.log("\nDeploying main AccessControlContract with library links...");
  const AccessControlContractFactory = await hre.ethers.getContractFactory("AccessControlContract", {
    libraries: {
      // 这里的键名 "EnvironmentalPolicyLogic" 必须与合约文件名完全一致
      // EnvironmentalPolicyLogic: environmentalPolicyLogic.address,
      // TemporalPolicyLogic: temporalPolicyLogic.address,

      // 注意：如果您的 ACC 还依赖其他库，也需要在这里一并链接
      // 例如: "DIDAttributePolicyLogic": didAttributePolicyLogic.address
    },
  });

  const AGC = await ethers.getContractFactory("AgentGovernanceContract");
  const DAC = await ethers.getContractFactory("DataAnchoringContract");
  const ILC = await ethers.getContractFactory("InteractionLogicContract");
  const agc = await AGC.deploy(_blsPubKeyList);
  const dac = await DAC.deploy();
  const ilc = await ILC.deploy(_blsPubKeyList, 1);
  await agc.deployed();
  console.log("AgentGovernance deployed to:", agc.address);
  await dac.deployed();
  console.log("DataAnchoring deployed to:", dac.address);
  await ilc.deployed();
  console.log("InteractionLogic deployed to:", ilc.address);
  // 第三步：部署主合约实例
  // 【重要】请检查您的 ACC 合约构造函数是否需要参数！
  // 如果构造函数需要参数（比如BLS公钥列表），您需要在这里传入。
  // 例如: const acc = await AccessControlContractFactory.deploy(blsKeys);
  const acc = await AccessControlContractFactory.deploy(); // 假设您的构造函数为空

  await acc.deployed();

  console.log(`\n✅ AccessControlContract deployed successfully to: ${acc.address}`);
}

main().catch(err => { console.error(err); process.exit(1); });
