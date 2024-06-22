// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "../math/Math.sol";
import "../mixer/ReferMixer.sol";
import "../mixer/MoneyMixer.sol";

interface IProtocol {
  struct DeploymentState {
    bool isDeploymentEnd;
    uint256 numInitialMember;
    uint256 endblock;
    bool firstSignerSetUp;
  }

  struct ProtocolParams {
    // Percentage send to parent
    Rational parentFee;
    // Encode fee
    uint256 protocolFee;
    uint256 joinFee;
    uint256 signerDepositFee;
  }

  struct SignerInfo {
    address currentSigner;
    address nextSigner;
    uint256 nextSignerIndex;
    mapping(address => bool) signerDeposit;
  }

  struct RoundInfo {
    // Basic round infomation
    uint256 number;
    uint256 roundEnd;
    uint256 roundLong;
    bool isEnd;
    // Signer infomation
    SignerInfo signerInfo;
    bool signerMoneyVerify;
    bool signerReferVerify;
  }

  function initialMemberRegister() external payable;
  function closeDeploymentState() external;
  function bidForNextSigner() external payable;
  function refundUnsuccessSigner() external;
  function startNewRound() external;
  function endRound() external;
  function requestRefer() external;
  function startRequestRefer(address account, uint256 nonce) external;
  function sendReferRequest(uint256 nonce, uint256 e) external;
  function signReferRequest(uint256 nonce, uint256 s) external;
  function onboardMember(uint256 c, uint256 s, uint256 y) external payable;
  function sendTransaction(uint256 index, uint256 e) external;
  function signTransaction(address account, uint256 e, uint256 r) external;
  function receiveTransaction(
    uint256 money,
    uint256 rno,
    uint256 c,
    uint256 s,
    uint256 y,
    uint256 t
  ) external;
  function referValidityCheck() external;
  function moneyValidityCheck() external;
  function unlockMR(uint256 index, uint256 e) external;
  function formNewMR(uint256 amount) external;
}
