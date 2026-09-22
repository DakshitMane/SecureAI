import { defineConfig } from "hardhat/config";
import hardhatToolboxMochaEthers from "@nomicfoundation/hardhat-toolbox-mocha-ethers";

export default defineConfig({
  solidity: "0.8.20",
  plugins: [hardhatToolboxMochaEthers],
  paths: {
    sources: "./l1_blockchain/contracts",
    tests: "./l1_blockchain/test",
    cache: "./cache",
    artifacts: "./artifacts"
  }
});