const hre = require("hardhat");
const fs = require("node:fs");
const path = require("node:path");

async function main() {
  console.log("Deploying Incognito AuditRegistry smart contract...");

  const [deployer] = await hre.ethers.getSigners();
  console.log(`Deploying with account: ${deployer.address}`);

  const AuditRegistry = await hre.ethers.getContractFactory("AuditRegistry");
  const registry = await AuditRegistry.deploy();

  await registry.waitForDeployment();
  const address = await registry.getAddress();
  const network = await hre.ethers.provider.getNetwork();

  const deploymentData = {
    contractAddress: address,
    chainId: Number(network.chainId),
    network: hre.network.name,
    deployer: deployer.address,
    deployedAt: new Date().toISOString(),
  };

  const outputPath = path.resolve(__dirname, "../deployment.json");
  fs.writeFileSync(outputPath, JSON.stringify(deploymentData, null, 2));

  console.log(`AuditRegistry successfully deployed to: ${address}`);
  console.log(`Chain ID: ${network.chainId}`);
  console.log(`Network: ${hre.network.name}`);
  console.log(`Deployment metadata written to: ${outputPath}`);

  return deploymentData;
}

if (require.main === module) {
  main()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error("Deployment failed:", error);
      process.exit(1);
    });
}

module.exports = { main };
