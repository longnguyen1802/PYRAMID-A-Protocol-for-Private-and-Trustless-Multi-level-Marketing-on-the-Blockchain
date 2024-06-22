// SPDX-License-Identifier: MIT

pragma solidity 0.8.20;

import "../interfaces/ICryptography.sol";
import "../interfaces/IReferMixer.sol";
import "../utilities/Time.sol";

contract ReferMixer is IReferMixer {
  modifier onlyProtocol() {
    require(msg.sender == protocol, "Only the protocol can call this function.");
    _;
  }

  modifier nonNullAddress(address _address) {
    require(_address != address(0), "Address cannot be null");
    _;
  }

  address immutable cryptography;
  address immutable protocol;
  PhaseControl phaseControl;

  // User => (nonce => bool)
  mapping(address => mapping(uint256 => bool)) public referIdentify;
  // nonce => message
  mapping(uint256 => uint256) public referMessage;
  // nonce => signature
  mapping(uint256 => uint256) public referSignature;

  uint256 numReferRequest;
  uint256 numReferOnboard;

  constructor(
    address _protocol,
    address _cryptography,
    uint256 _phaseLength
  ) nonNullAddress(_protocol) nonNullAddress(_cryptography) {
    protocol = _protocol;
    cryptography = _cryptography;
    phaseControl = PhaseControl(4, _phaseLength, block.number);
  }

  function recordReferRequest(address account, uint256 nonce) external onlyProtocol {
    require(phaseControl.currentPhase == 1, "Not in refer phase");
    referIdentify[account][nonce] = true;
  }

  function recordReferMessage(address account, uint256 nonce, uint256 message) external onlyProtocol {
    require(referIdentify[account][nonce], "Member not make refer request");
    require(phaseControl.currentPhase == 1, "Not in refer phase");
    referMessage[nonce] = message;
  }

  function recordReferSignature(uint256 nonce, uint256 sig) external onlyProtocol {
    require(phaseControl.currentPhase == 2, "Not in sign phase");
    referSignature[nonce] = sig;
    numReferRequest++;
  }

  function verifyReferSignature(
    address account,
    uint256 signerPubKey,
    uint256 c,
    uint256 s,
    uint256 y
  ) public {
    require(phaseControl.currentPhase >= 3 && phaseControl.currentPhase <= 3, "Not in onboard phase");
    // Check Signature
    require(
      ICryptography(cryptography).BSverifyBlindSignature(c, s, y, signerPubKey, account),
      "Invalid Schnoor signature"
    );
    numReferOnboard++;
  }

  function doValidityCheck() external view onlyProtocol(){
    require(phaseControl.currentPhase >=4);
    require(numReferRequest <= numReferOnboard , "Number of refer onboard is more than number of request");
  }

  /********************************* Phase control ****************************/
  function moveToSignPhase() external onlyProtocol {
    require(phaseControl.currentPhase == 1, "Not in refer phase");
    checkCurrentPhaseEnd(phaseControl, block.number);
    moveToNextPhase(phaseControl, block.number);
  }

  function moveToOnboardPhase() external onlyProtocol {
    require(phaseControl.currentPhase == 2, "Not in sign phase");
    checkCurrentPhaseEnd(phaseControl, block.number);
    moveToNextPhase(phaseControl, block.number);
  }

  function moveToValidityCheckPhase() external onlyProtocol(){
    require(phaseControl.currentPhase == 3, "Not in onboard phase");
    checkCurrentPhaseEnd(phaseControl, block.number);
    moveToNextPhase(phaseControl, block.number);
  }
  // New round start
  function reset() external onlyProtocol {
    require(phaseControl.currentPhase == 4, "Not in final phase");
    resetPhase(phaseControl, block.number);
    numReferOnboard = 0;
    numReferRequest = 0;
  }

  function getCurrentPhase() public view returns (uint256) {
    return phaseControl.currentPhase;
  }
}
