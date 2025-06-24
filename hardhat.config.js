/** @type import('hardhat/config').HardhatUserConfig */
require("@nomiclabs/hardhat-ethers");
module.exports = {
  defaultNetwork: "hardhat",
  solidity: {
    version: "0.8.24",
    settings: {
      viaIR: true,
      // 同时最好打开 optimizer，配合 IR 能进一步减少栈深度
      optimizer: {
        enabled: true,
        runs: 1000000
      }
    }
  },
  paths: {
    sources: "./contracts",
    tests:   "./tests/solidity",
    cache:   "./cache/hardhat",
    artifacts: "./artifacts"
  },
  networks: {
    hardhat: {
      chainId: 1337
    }
  }
};
