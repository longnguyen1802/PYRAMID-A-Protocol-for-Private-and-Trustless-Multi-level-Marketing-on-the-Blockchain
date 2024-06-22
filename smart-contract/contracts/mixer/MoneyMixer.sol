// SPDX-License-Identifier: MIT

pragma solidity 0.8.20;

import "../interfaces/IMoneyMixer.sol";
import "../interfaces/ICryptography.sol";

/* Phase
 * 1: Send phase (Only accept send transaction)
 * 2: Sign phase (Only signer allow to sign transaction)
 * 3: Receive phase (Only receive transaction allow)
 * 4: Verify signer phase
 */

contract MoneyMixer is IMoneyMixer {
  modifier onlyProtocol() {
    require(msg.sender == protocol, "Only the protocol can call this function.");
    _;
  }

  modifier nonNullAddress(address _address) {
    require(_address != address(0), "Address cannot be null");
    _;
  }

  uint256 constant numeratorParentFee = 1;
  uint256 constant denominatorParentFee = 2;
  address immutable protocol;
  address immutable cryptography;
  PhaseControl phaseControl;
  uint256 totalSendMoney;
  uint256 totalReceiveMoney;
  // Account => (message => MR index)
  mapping(address => mapping(uint256 => uint256)) public distributeMoneyMessage;
  // Account => (message => Signature)
  mapping(address => mapping(uint256 => uint256)) public distributeMoneySignature;
  // Account => money
  mapping(address => uint256) public receiveTransactionConfirm;

  constructor(
    address _protocol,
    address _cryptography,
    uint256 _phaseLength
  ) nonNullAddress(_protocol) nonNullAddress(_cryptography) {
    protocol = _protocol;
    cryptography = _cryptography;
    totalSendMoney = 0;
    totalReceiveMoney = 0;
    phaseControl = PhaseControl(4, _phaseLength, block.number);
  }

  function recordSendTransaction(address account, uint256 mrIndex, uint256 blindMsg) external onlyProtocol {
    require(phaseControl.currentPhase == 1);
    distributeMoneyMessage[account][blindMsg] = mrIndex;
    totalSendMoney += IMemberAccount(account).getMRValue(mrIndex);
  }

  function recordSendSignature(address account, uint256 blindMsg, uint256 sig) external onlyProtocol {
    require(phaseControl.currentPhase == 2);
    distributeMoneySignature[account][blindMsg] = sig;
  }

  function recordReceiveTransaction(
    address account,
    uint256 money,
    uint256 rno,
    uint256 c,
    uint256 s,
    uint256 y,
    uint256 t,
    uint256 signerPubKey
  ) external onlyProtocol {
    require(phaseControl.currentPhase == 3, "Not in receive phase");
    uint256 z = uint256(keccak256(abi.encode(money,rno)));
    receiveTransactionConfirm[account] += (money * numeratorParentFee) / denominatorParentFee;
    totalReceiveMoney += money;
    PartialBlindSignature memory pbs = PartialBlindSignature(c,s,y,t);
    bool check = ICryptography(cryptography).PBSverifyBlindSignature(pbs, z, signerPubKey, account);
    require(
      check,
      "Invalid Partial Blind signature"
    );
  }

  function doValidityCheck() external view onlyProtocol {
    require(phaseControl.currentPhase >= 4);
    require(totalReceiveMoney <= totalSendMoney, "Total send money more than total receive money");
  }

  function spendReceiveTransactionMoney(address account, uint256 amount) external onlyProtocol {
    require(receiveTransactionConfirm[account] >= amount);
    receiveTransactionConfirm[account] -= amount;
  }
  /********************************* Phase control ****************************/
  function moveToSignPhase() external onlyProtocol {
    require(phaseControl.currentPhase == 1, "Not in send phase");
    checkCurrentPhaseEnd(phaseControl, block.number);
    moveToNextPhase(phaseControl, block.number);
  }

  function moveToReceivePhase() external onlyProtocol {
    require(phaseControl.currentPhase == 2, "Not in sign phase");
    checkCurrentPhaseEnd(phaseControl, block.number);
    moveToNextPhase(phaseControl, block.number);
  }

  function moveToValidityCheckPhase() external onlyProtocol {
    require(phaseControl.currentPhase == 3, "Not in receive check phase");
    checkCurrentPhaseEnd(phaseControl, block.number);
    moveToNextPhase(phaseControl, block.number);
  }
  // New round start
  function reset() external onlyProtocol {
    require(phaseControl.currentPhase == 4, "Not in final phase");
    resetPhase(phaseControl, block.number);
    totalReceiveMoney = 0;
    totalSendMoney = 0;
  }
  // Get function
  function getSendMessageIndex(address account, uint256 e) public view returns (uint256) {
    return distributeMoneyMessage[account][e];
  }
}
