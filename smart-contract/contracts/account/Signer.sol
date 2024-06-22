// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "../interfaces/IProtocol.sol";
function recordBidForSigner(
  IProtocol.SignerInfo storage signerInfo,
  address account,
  uint256 signIndex
) {
  require(
    signIndex < signerInfo.nextSignerIndex || signerInfo.nextSignerIndex == 0,
    "Sign index is larger than current next signer index"
  );
  signerInfo.nextSigner = account;
  signerInfo.nextSignerIndex = signIndex;
  signerInfo.signerDeposit[account] = true;
}

function removeUnsuccessRegister(IProtocol.SignerInfo storage signerInfo, address account) {
  require(signerInfo.signerDeposit[account]);
  require(signerInfo.currentSigner != msg.sender);
  require(signerInfo.nextSigner != msg.sender);
  signerInfo.signerDeposit[msg.sender] = false;
}
