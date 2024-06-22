// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "../interfaces/IProtocol.sol";
import "../interfaces/IMemberAccount.sol";
import "hardhat/console.sol";

contract MemberAccount is IMemberAccount {
  event UpdateSignIndex(uint256 index);

  modifier nonNullAddress(address _address) {
    require(_address != address(0), "Address cannot be null");
    _;
  }

  modifier onlyProtocol() {
    require(msg.sender == protocol, "Only the protocol can call this function.");
    _;
  }

  mapping(address => uint256) public allowances;
  // Normal account information
  address immutable protocol;
  address immutable cryptography;
  uint256 immutable sendKey;
  uint256 immutable receiveKey;

  // Money record
  uint256 totalURT;
  mapping(uint256 => MR) public moneyRecord;

  // Signer support information
  uint256 immutable pubKey;
  uint256 immutable signNonce;
  uint256 signIndex;
  uint256 immutable signerDepositFee;

  // Fee information
  uint256 immutable protocolFee;
  uint256 immutable joinFee;
  constructor(
    address _protocol,
    address _cryptography,
    uint256 _pubKey,
    uint256 _sendKey,
    uint256 _receiveKey,
    uint256 _signNonce,
    uint256 _signerDepositFee,
    uint256 _protocolFee,
    uint256 _joinFee
  ) nonNullAddress(_protocol) nonNullAddress(_cryptography) {
    protocol = _protocol;
    cryptography = _cryptography;
    pubKey = _pubKey;
    sendKey = _sendKey;
    receiveKey = _receiveKey;
    signIndex = block.number;
    signNonce = _signNonce;
    signerDepositFee = _signerDepositFee;
    protocolFee = _protocolFee;
    joinFee = _joinFee;
  }

  function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
    return interfaceId == type(IMemberAccount).interfaceId;
  }

  function setSignIndex(uint256 _signIndex) public onlyProtocol {
    signIndex = _signIndex;
    emit UpdateSignIndex(_signIndex);
  }

  function getSignIndex() public view returns (uint256) {
    return signIndex;
  }

  function increaseSignIndex(uint256 amount) external {
    signIndex += amount;
  }

  function getSignKey() public view returns (uint256) {
    return pubKey;
  }

  function processMR(uint256 index) external onlyProtocol {
    require(moneyRecord[index].state == State.Lock, "State is not Lock");
    moneyRecord[index].state = State.InProcess;
  }

  function lockMR(uint256 index) external {
    require(msg.sender == protocol);
    moneyRecord[index].state = State.InProcess;
  }

  function unlockMR(uint256 index) external {
    require(msg.sender == protocol);
    require(moneyRecord[index].state == State.InProcess);
    moneyRecord[index].state = State.Unlock;
  }

  function getMoneyRecordState(uint256 index) public view returns (State) {
    return moneyRecord[index].state;
  }

  function getMRValue(uint256 index) public view returns (uint256) {
    return moneyRecord[index].money;
  }

  function createMR(uint256 amount) external onlyProtocol {
    totalURT += 1;
    moneyRecord[totalURT] = MR(amount, State.Lock);
  }

  /************* Initial Member Register ***********************/
  // Some one need to deposit money so no need to check signature
  function registerInitialMember(uint256 _value) public payable {
    require(isValidProtocolAddress(protocol), "Invalid protocol address");
    IProtocol(protocol).initialMemberRegister{value: _value}();
  }

  /************************************ Refer Workflow **********************************/
  /**
   *
   * @param nonce Nonce for refer request
   * @param e Message for refer request
   * @param sigR Part of elgama signature
   * @param sigS Part of elgama signature
   */
  function sendReferRequest(uint256 nonce, uint256 e, uint256 sigR, uint256 sigS) external {
    uint256 m = uint256(keccak256(abi.encode(nonce, e)));
    require(ICryptography(cryptography).verifyElgamaSignature(m, sigR, sigS, receiveKey));
    IProtocol(protocol).sendReferRequest(nonce, e);
  }

  function startRequestRefer(address account, uint256 nonce, uint256 sigR, uint256 sigS) public {
    uint256 m = uint256(keccak256(abi.encode(account, nonce)));
    require(
      ICryptography(cryptography).verifyElgamaSignature(m, sigR, sigS, receiveKey),
      "Invalid elgama signature"
    );
    IProtocol(protocol).startRequestRefer(account, nonce);
  }

  function signReferRequest(uint256 nonce, uint256 s, uint256 sigR, uint256 sigS) public {
    uint256 m = uint256(keccak256(abi.encode(nonce, s)));
    require(
      ICryptography(cryptography).verifyElgamaSignature(m, sigR, sigS, receiveKey),
      "Invalid elgama signature"
    );
    IProtocol(protocol).signReferRequest(nonce, s);
  }

  function onBoard(uint256 c, uint256 s, uint256 y, uint256 sigR, uint256 sigS) external payable {
    require(msg.value >= protocolFee + joinFee, "Insufficient fee");
    uint256 m = uint256(keccak256(abi.encode(c, s, y)));
    require(
      ICryptography(cryptography).verifyElgamaSignature(m, sigR, sigS, receiveKey),
      "Invalid elgama signature"
    );
    require(isValidProtocolAddress(protocol), "Invalid protocol address");
    IProtocol(protocol).onboardMember{value: protocolFee + joinFee}(c, s, y);
  }

  /************************************ Money Workflow **********************************/
  function sendTransaction(uint256 mrIndex, uint256 blindMsg, uint256 sigR, uint256 sigS) external {
    // Call the interface
    uint256 m = uint256(keccak256(abi.encode(mrIndex, blindMsg)));
    require(
      ICryptography(cryptography).verifyElgamaSignature(m, sigR, sigS, sendKey),
      "Invalid elgama signature"
    );
    IProtocol(protocol).sendTransaction(mrIndex, blindMsg);
  }

  function receiveTransaction(
    uint256 money,
    uint256 rno,
    uint256 c,
    uint256 s,
    uint256 y,
    uint256 t,
    uint256 sigR,
    uint256 sigS
  ) external {
    // Call the interface
    uint256 m = uint256(keccak256(abi.encode(money, rno, c, s, y, t)));
    require(
      ICryptography(cryptography).verifyElgamaSignature(m, sigR, sigS, receiveKey),
      "Invalid elgama signature"
    );
    IProtocol(protocol).receiveTransaction(money, rno, c, s, y, t);
  }

  function signTransaction(
    address account,
    uint256 e,
    uint256 r,
    uint256 sigR,
    uint256 sigS
  ) external {
    // Call the interface
    uint256 m = uint256(keccak256(abi.encode(account, e, r)));
    require(
      ICryptography(cryptography).verifyElgamaSignature(m, sigR, sigS, receiveKey),
      "Invalid elgama signature"
    );
    IProtocol(protocol).signTransaction(account, e, r);
  }

  /******************* Other function *******************/
  function bidSigner() external payable {
    require(msg.value == signerDepositFee, "Insufficient deposit fee");
    require(isValidProtocolAddress(protocol), "Invalid protocol address");
    IProtocol(protocol).bidForNextSigner{value: signerDepositFee}();
  }

  function claimRefundSigner() external {
    IProtocol(protocol).refundUnsuccessSigner();
  }

  receive() external payable {}

  function approve(uint256 amount, uint256 sigR, uint256 sigS) external {
    uint256 m = uint256(keccak256(abi.encode(msg.sender, amount)));
    require(ICryptography(cryptography).verifyElgamaSignature(m, sigR, sigS, receiveKey));
    allowances[msg.sender] += amount;
  }

  function withdraw(uint256 amount) external {
    require(amount <= allowances[msg.sender], "Insufficient contract balance");
    allowances[msg.sender] -= amount;
    payable(msg.sender).transfer(amount);
  }

  function isValidProtocolAddress(address _protocol) internal pure returns (bool) {
    // Add your validation logic here, e.g., check against a whitelist
    return _protocol != address(0);
  }
}
