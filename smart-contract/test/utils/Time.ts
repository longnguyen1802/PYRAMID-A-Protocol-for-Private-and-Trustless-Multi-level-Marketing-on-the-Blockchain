import {ethers} from 'hardhat';
import {network} from 'hardhat';
import {time} from '@nomicfoundation/hardhat-network-helpers';
import {networkUrls} from './Constant';
const externalProvider = new ethers.JsonRpcProvider(networkUrls[network.name]);

// Function to mine a specified number of blocks
export async function mineBlocks(numberOfBlocks: number): Promise<void> {
  for (let i = 0; i < numberOfBlocks; i++) {
    await network.provider.send('evm_mine');
  }
}

// Get the current block number
export async function getCurrentBlockNumber(): Promise<number> {
  if (network.name != 'hardhat') {
    let currentBlockNumber = await externalProvider.getBlockNumber();
    return currentBlockNumber;
  } else {
    let currentBlockNumber = await ethers.provider.getBlockNumber();
    return currentBlockNumber;
  }
}

// Advance block to a specific number
export async function advanceBlockTo(targetBlockNumber: number): Promise<void> {
  if (network.name != 'hardhat') {
    const currentBlock = await getCurrentBlockNumber();
    if (targetBlockNumber < currentBlock) {
      throw new Error(`Target block number (${targetBlockNumber}) is in the past`);
    }

    const blocksToMine = targetBlockNumber - currentBlock;
    await mineBlocks(blocksToMine);
  } else {
    //const currentBlock = await getCurrentBlockNumber();
    await time.advanceBlockTo(targetBlockNumber);
  }
}
