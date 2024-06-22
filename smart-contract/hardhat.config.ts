import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const config: HardhatUserConfig = {
  defaultNetwork: "hardhat",
  solidity: "0.8.20",
  networks: {
    hardhat: {
      chainId: 1337, // Hardhat's default chain ID
    },
    ganache: {
      url: "http://localhost:8545", // Ganache's default RPC URL
      accounts: [
        "0xca3547a47684862274b476b689f951fad53219fbde79f66c9394e30f1f0b4904",
        "0x4bad9ef34aa208258e3d5723700f38a7e10a6bca6af78398da61e534be792ea8",
        "0xffc03a3bd5f36131164ad24616d6cde59a0cfef48235dd8b06529fc0e7d91f7c",
        "0x380c430a9b8fa9cce5524626d25a942fab0f26801d30bfd41d752be9ba74bd98",
        "0x0123456789012345678901234567890123456789012345678901234567890123"
      ],
    },
    ganachecli: {
      url: "http://localhost:7545",
    }
  }
};

export default config;
