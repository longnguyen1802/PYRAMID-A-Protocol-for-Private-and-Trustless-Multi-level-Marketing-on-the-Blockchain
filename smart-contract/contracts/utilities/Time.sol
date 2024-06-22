// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

struct PhaseControl {
  uint256 currentPhase;
  uint256 phaseLength;
  uint256 phaseEndBlock;
}

function checkCurrentPhaseEnd(
  PhaseControl storage phase,
  uint256 currentBlock
) view returns (bool) {
  require(currentBlock >= phase.phaseEndBlock);
  return true;
}

function moveToNextPhase(PhaseControl storage phase, uint256 currentBlock) {
  require(currentBlock >= phase.phaseEndBlock);
  phase.currentPhase = phase.currentPhase + 1;
  phase.phaseEndBlock += phase.phaseLength;
}

function resetPhase(PhaseControl storage phase, uint256 currentBlock) {
  phase.currentPhase = 1;
  phase.phaseEndBlock = currentBlock + phase.phaseLength;
}
