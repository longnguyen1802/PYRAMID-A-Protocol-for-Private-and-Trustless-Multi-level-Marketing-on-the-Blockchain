// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";
enum State {
  Initial,
  Lock,
  InProcess,
  Unlock
}
interface IMemberAccount is IERC165 {
  struct MR {
    uint256 money;
    State state;
  }

  struct Rational {
    uint128 numerator;
    uint128 denominator;
  }

  function setSignIndex(uint256 _signIndex) external;
  function getSignIndex() external view returns (uint256);
  function increaseSignIndex(uint256 amount) external;
  function getSignKey() external view returns (uint256);
  function processMR(uint256 index) external;
  function lockMR(uint256 index) external;
  function unlockMR(uint256 index) external;
  function getMoneyRecordState(uint256 index) external view returns (State);
  function getMRValue(uint256 index) external view returns (uint256);
  function createMR(uint256 amount) external;
  function startRequestRefer(address account, uint256 nonce, uint256 sigR, uint256 sigS) external;
  function sendReferRequest(uint256 nonce, uint256 e, uint256 sigR, uint256 sigS) external;
  function signReferRequest(uint256 nonce, uint256 s, uint256 sigR, uint256 sigS) external;
  function onBoard(uint256 c, uint256 s, uint256 y, uint256 sigR, uint256 sigS) external payable;

  function registerInitialMember(uint256 value) external payable;

  function sendTransaction(uint256 index, uint256 e, uint256 sigR, uint256 sigS) external;
  function receiveTransaction(
    uint256 money,
    uint256 rno,
    uint256 c,
    uint256 s,
    uint256 y,
    uint256 t,
    uint256 sigR,
    uint256 sigS
  ) external;

  function signTransaction(
    address account,
    uint256 e,
    uint256 r,
    uint256 sigR,
    uint256 sigS
  ) external;

  function bidSigner() external payable;
  function claimRefundSigner() external;
}
