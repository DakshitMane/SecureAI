import hardhat from "hardhat";

async function main() {
    const AuditGate = await hardhat.ethers.getContractFactory("AuditGate");
    const gate = await AuditGate.deploy();
    await gate.waitForDeployment();
    console.log(`🚀 AuditGate contract deployed to target address: ${await gate.getAddress()}`);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
