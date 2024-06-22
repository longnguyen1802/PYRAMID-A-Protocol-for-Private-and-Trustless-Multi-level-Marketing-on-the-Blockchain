// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IReferMixer {
  event ReferRequestRecorded(address account, uint256 nonce);
  event ReferMessageRecorded(address account, uint256 nonce, uint256 e);
  event ReferSignatureRecorded(uint256 nonce, uint256 s);

  function recordReferRequest(address account, uint256 nonce) external;
  function recordReferMessage(address account, uint256 nonce, uint256 e) external;
  function recordReferSignature(uint256 nonce, uint256 s) external;
  function verifyReferSignature(
    address account,
    uint256 signerPubKey,
    uint256 c,
    uint256 s,
    uint256 y
  ) external;

  function moveToSignPhase() external;
  function moveToOnboardPhase() external;
  function moveToValidityCheckPhase() external;
  function doValidityCheck() external;
  function reset() external;
}
