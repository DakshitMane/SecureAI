import hardhat from "hardhat";

// Custom helper function to print the deployment summary to the terminal
function printDeploymentReceipt(address) {
    console.log("----------------------------------------------------------");
    console.log("🏆 DEPLOYMENT SUCCESSFUL!");
    console.log(`📍 Contract Core Target Address: ${address}`);
    console.log("==========================================================");
}

async function main() {
    console.log("==========================================================");
    console.log("⛓️ RUNNING LAYER-1 LOCAL EVM TESTNET DEPLOYMENT ENGINE");
    console.log("==========================================================");

    // Compile and fetch contract factories out of the l1_blockchain path mapping
    const AuditGate = await hardhat.ethers.getContractFactory("AuditGate");

    console.log("Deploying AuditGate verifier and state storage checkpoint...");
    const gate = await AuditGate.deploy();
    await gate.waitForDeployment();

    const deployedAddress = await gate.getAddress();

    // Calling our JavaScript helper function cleanly
    printDeploymentReceipt(deployedAddress);
}

// Standard Hardhat error-handling wrapper execution pattern
main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
