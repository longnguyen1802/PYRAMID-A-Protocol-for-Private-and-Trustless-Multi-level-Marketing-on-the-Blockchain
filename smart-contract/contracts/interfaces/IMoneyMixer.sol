// SPDX-License-Identifier: MIT

pragma solidity 0.8.20;

import "../interfaces/IMemberAccount.sol";
import "../utilities/Time.sol";

interface IMoneyMixer {
  /**
   * @dev Records a send transaction.
   * @param account The account to record the transaction for.
   * @param index The index of the transaction.
   * @param e The value to be recorded.
   */
  function recordSendTransaction(address account, uint256 index, uint256 e) external;

  /**
   * @dev Records a send signature.
   * @param account The account to record the signature for.
   * @param e The value to be recorded.
   * @param r The value to be recorded.
   */
  function recordSendSignature(address account, uint256 e, uint256 r) external;

  /**
   * @dev Records a receive transaction.
   * @param account The account to record the transaction for.
   * @param money The amount of money to be recorded.
   * @param rno The current round
   * @param c Signature
   * @param s Signature
   * @param y Signature
   * @param t Signature
   * @param signerPubKey The public key of the signer.
   */
  function recordReceiveTransaction(
    address account,
    uint256 money,
    uint256 rno,
    uint256 c,
    uint256 s,
    uint256 y,
    uint256 t,
    uint256 signerPubKey
  ) external;

  function spendReceiveTransactionMoney(address account, uint256 amount) external;

  /**
   * @dev Moves the contract to the sign phase.
   */
  function moveToSignPhase() external;

  /**
   * @dev Moves the contract to the receive phase.
   */
  function moveToReceivePhase() external;

  /**
   * @dev Moves the contract to the validity check phase.
   */
  function moveToValidityCheckPhase() external;

  /**
   * @dev Resets the mixer.
   */
  function reset() external;

  function doValidityCheck() external view;

  function getSendMessageIndex(address account, uint256 e) external view returns (uint256);
}
