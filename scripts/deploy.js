const { ethers } = require("hardhat");

async function main() {
  const AGC = await ethers.getContractFactory("AgentGovernanceContract");
  const agc = await AGC.deploy();
  await agc.deployed();
  console.log("AgentGovernance deployed to:", agc.address);
}

main().catch(err => { console.error(err); process.exit(1); });
