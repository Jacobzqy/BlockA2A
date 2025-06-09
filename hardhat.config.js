/** @type import('hardhat/config').HardhatUserConfig */
require("@nomiclabs/hardhat-ethers");
module.exports = {
  defaultNetwork: "hardhat",
  solidity: "0.8.28",
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
