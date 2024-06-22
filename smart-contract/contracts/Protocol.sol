// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

//import "hardhat/console.sol";
import "./account/Signer.sol";
import "./interfaces/IProtocol.sol";
import "./interfaces/IMemberAccount.sol";
import "./interfaces/IMoneyMixer.sol";
import "./interfaces/IReferMixer.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165.sol";

contract Protocol is IProtocol {

    modifier nonNullAddress(address _address) {
        require(_address != address(0), "Address cannot be null");
        _;
    }

    // Events
    event RequestRefer(address indexed signer);
    event SendTransactionRequest(
        address indexed signer,
        uint256 index,
        uint256 e
    );

    // ************************************************** PROTOCOL ATTRIBUTE ***********************************************
    // Protocol params
    ProtocolParams public params;
    // Deployment phase
    DeploymentState public deployState;
    // All other phases
    RoundInfo roundInfo;

    // Address of mixer
    address immutable mixerControl;
    address moneyMixer;
    address referMixer;

    // Keep track of member
    uint256 public numberMember;
    mapping(address => bool) public members;

    /*
        Constructor
        Set up all protocol parameters
     */
    constructor(
        uint256 numeParentFee,
        uint256 demoParentFee,
        uint256 _protocolFee,
        uint256 _joinFee,
        uint256 _signerDepositFee,
        uint256 deploymentLength,
        uint256 _roundLong
    ) {
        mixerControl = msg.sender;
        params = ProtocolParams(
            Rational(numeParentFee, demoParentFee),
            _protocolFee,
            _joinFee,
            _signerDepositFee
        );

        deployState = DeploymentState(
            false,
            0,
            block.number + deploymentLength,
            false
        );

        roundInfo.number = 0;
        roundInfo.roundLong = _roundLong;
        roundInfo.isEnd = true;

        numberMember = 0;

    }

    function setUpMixer(address _moneyMixer,address _referMixer) nonNullAddress(_moneyMixer) nonNullAddress(_referMixer) external {
        require(msg.sender == mixerControl);
        moneyMixer = _moneyMixer;
        referMixer = _referMixer;
    }
    /********************************  DEPLOYMENT PHASE *********************************/
    /*
    Register for initial member
    Check timestamp
    Contribute the protocol fee
    Set up the send key for account (optional sign key )
     */

    function initialMemberRegister() public payable {
        require(msg.value >= params.protocolFee,"Insufficient protocol fee");
        require(block.number <= deployState.endblock,"Not in deployment state");
        // Interface check
        ERC165 memberAccountChecker = ERC165(msg.sender);
        require(memberAccountChecker.supportsInterface(type(IMemberAccount).interfaceId), "MemberAccount contract not found or does not support IMemberAccount interface");
        
        members[msg.sender] = true;
        if(deployState.numInitialMember <= 0) {
            roundInfo.signerInfo.nextSigner = msg.sender;
        }
        deployState.numInitialMember++;
        numberMember++;
        IMemberAccount(msg.sender).setSignIndex(block.number);
    }

    /*
    Close the inital member register state
    Check timestamp
    Can be call by anyone
    End the initial state
     */
    function closeDeploymentState() public {
        require(block.number > deployState.endblock,"Deployment state not end");
        deployState.isDeploymentEnd = true;
    }

    /************************************ Signer Rotation Flow *****************************************/
    /*  Bid to become next signer
        Requirement :
            Account not being banned for signer (Caught cheat previously)
            Chose the smallest Index
            Increase the index of member being chose by current number member
     */

    function bidForNextSigner() public payable {
        require(deployState.isDeploymentEnd);
        require(!roundInfo.isEnd);
        require(members[msg.sender]);
        require(msg.value == params.signerDepositFee);
        uint256 signIndex = IMemberAccount(msg.sender).getSignIndex();
        recordBidForSigner(roundInfo.signerInfo, msg.sender, signIndex);
    }

    function refundUnsuccessSigner() public {
        require(members[msg.sender]);
        removeUnsuccessRegister(roundInfo.signerInfo, msg.sender);
        payable(msg.sender).transfer(params.signerDepositFee);
    }

    function refundDepositSigner() public {
        require(roundInfo.signerInfo.currentSigner == msg.sender);
        require(roundInfo.signerMoneyVerify && roundInfo.signerReferVerify);
        payable(msg.sender).transfer(params.signerDepositFee);
    }

    /****************************************** MAIN FLOW DO ROUND BY ROUND *****************************/
    /*
        Start a new round with new signer and allow for bid next signer 
        Requirement:
            Round not in process
     */
    function startNewRound() public {
        require(deployState.isDeploymentEnd,"Deployment not end");
        require(roundInfo.isEnd,"Previous round not end");
        // Mofidy Signer info state
        roundInfo.signerInfo.currentSigner = roundInfo.signerInfo.nextSigner;
        roundInfo.signerInfo.nextSigner = address(0);
        roundInfo.signerInfo.nextSignerIndex = 0;
        // Modify Round info state
        roundInfo.isEnd = false;
        roundInfo.roundEnd += roundInfo.roundLong;
        IReferMixer(referMixer).reset();
        IMoneyMixer(moneyMixer).reset();
        IMemberAccount(roundInfo.signerInfo.currentSigner).increaseSignIndex(
            numberMember
        );
    }

    /*
        End current round
        Requirements:
            Timestamp require
            Call function to decide cheat signer
            Refund for signer
     */
    function endRound() public {
        require(roundInfo.roundEnd <= block.number,"Round still in time");
        require(roundInfo.isEnd == false,"Round already end");
        roundInfo.signerInfo.signerDeposit[
            roundInfo.signerInfo.currentSigner
        ] = false;
        roundInfo.isEnd = true;
    }

    /*  REFER WORKFLOW */

    /*
        STEP 1: Inner member send request to refer new member
     */
    function requestRefer() public {
        require(members[msg.sender],"Not member of protocol");
        emit RequestRefer(msg.sender);
    }
    /**
     *
     * @param account Address of member that want to make a refer
     * @param nonce Public nonce generate by Signer
     */
    function startRequestRefer(address account, uint256 nonce) public {
        require(msg.sender == roundInfo.signerInfo.currentSigner,"Not current signer");
        IReferMixer(referMixer).recordReferRequest(account, nonce);
    }

    /**
     * STEP 2: Signer generate nonce
     * @param nonce : Public nonce generate by signer
     * @param e :     Refer message (Blind)
     * e = 
     */
    function sendReferRequest(uint256 nonce, uint256 e) public {
        require(members[msg.sender],"Not member of protocol");
        IReferMixer(referMixer).recordReferMessage(msg.sender, nonce, e);
    }
    /**
     * STEP 3: Signer sign the refer message
     * @param nonce : Public nonce generate by signer
     * @param s     : Refer signature
     */
    function signReferRequest(uint256 nonce, uint256 s) public {
        require(msg.sender == roundInfo.signerInfo.currentSigner,"Not current signer");
        IReferMixer(referMixer).recordReferSignature(nonce, s);
    }

    /**
     * STEP 4: Verification and onboard new member
     * @param c : Original message
     * @param s : Signature
     * @param y : Signature
     */
    function onboardMember(uint256 c, uint256 s,uint256 y) public payable{
        require(msg.value >= params.joinFee + params.protocolFee,"Insufficient fee");
        // Interface check
        ERC165 memberAccountChecker = ERC165(msg.sender);
        require(memberAccountChecker.supportsInterface(type(IMemberAccount).interfaceId), "MemberAccount contract not found or does not support IMemberAccount interface");
        uint256 signerPubKey = IMemberAccount(
            roundInfo.signerInfo.currentSigner
        ).getSignKey();
        members[msg.sender] = true;
        numberMember+=1;
        IReferMixer(referMixer).verifyReferSignature(
            msg.sender,
            signerPubKey,
            c,
            s,
            y
        );
        // Form an MR
        IMemberAccount(msg.sender).createMR(params.joinFee);
    }

    function referValidityCheck() public {
        roundInfo.signerReferVerify = true;
        IReferMixer(referMixer).doValidityCheck();
    }
    /* 
        DISTRIBUTION MONEY WORKFLOW
     */

    /**
     * PHASE 1: Send transaction request
     * @param mrIndex : Index of the MR
     * @param blindMsg : Blind message
     */
    function sendTransaction(uint256 mrIndex, uint256 blindMsg) public {
        require(members[msg.sender],"Not member of protocol");
        emit SendTransactionRequest(msg.sender, mrIndex, blindMsg);
        IMoneyMixer(moneyMixer).recordSendTransaction(msg.sender, mrIndex, blindMsg);
        IMemberAccount(msg.sender).processMR(mrIndex);
    }

    /**
     * PHASE 2: Signer sign the transaction send request
     * @param account : Address of the account send transaction
     * @param e : Blind message
     * @param r : Signature sign by signer
     */
    function signTransaction(address account, uint256 e, uint256 r) public {
        require(msg.sender == roundInfo.signerInfo.currentSigner,"Not current signer");
        // Verify signer computation
        IMoneyMixer(moneyMixer).recordSendSignature(account, e, r);
    }

    /**
     * PHASE 3: Send receive request
     * @param money : Amount of money in MR
     * @param rno     Current round
     * @param c   Part of signature
     * @param s   Part of signature
     * @param y   Part of signature
     * @param t   Part of signature
     */
    function receiveTransaction(
        uint256 money,
        uint256 rno,
        uint256 c,
        uint256 s,
        uint256 y,
        uint256 t
    ) public {
        uint256 signerPubKey = IMemberAccount(
            roundInfo.signerInfo.currentSigner
        ).getSignKey();
        IMoneyMixer(moneyMixer).recordReceiveTransaction(
            msg.sender,
            money,
            rno,
            c,
            s,
            y,
            t,
            signerPubKey
        );
    }

    /**
     * PHASE 4: Validity check
     */
    function moneyValidityCheck() public {
        roundInfo.signerMoneyVerify = true;
        IMoneyMixer(moneyMixer).doValidityCheck();
    }

    function formNewMR(uint256 amount) public {
        require(members[msg.sender],"Not member of protocol");
        require(roundInfo.signerMoneyVerify,"Lastest round caught cheat signer");
        IMoneyMixer(moneyMixer).spendReceiveTransactionMoney(msg.sender,amount);
        IMemberAccount(msg.sender).createMR(amount);
    }

    function unlockMR(uint256 index,uint256 e) public {
        require(members[msg.sender],"Not member of protocol");
        require(roundInfo.signerMoneyVerify,"Lastest round caught cheat signer");
        require(index!=0,"Invalid MR index");
        require(IMoneyMixer(moneyMixer).getSendMessageIndex(msg.sender, e)==index,"Require an send transaction request with index");
        IMemberAccount(msg.sender).unlockMR(index);
    }
    /*************************** Phase control *************************************/
    function startSignPhaseForReferMixer() external {
        IReferMixer(referMixer).moveToSignPhase();
    }

    function startOnboardPhaseForReferMixer() external {
        IReferMixer(referMixer).moveToOnboardPhase();
    }

    function startValidityCheckPhaseForReferMixer() external {
        IReferMixer(referMixer).moveToValidityCheckPhase();
    }

    function startSignPhaseForMoneyMixer() external {
        IMoneyMixer(moneyMixer).moveToSignPhase();
    }

    function startReceivePhaseForMoneyMixer() external {
        IMoneyMixer(moneyMixer).moveToReceivePhase();
    }

    function startValidityCheckPhaseForMoneyMixer() external {
        IMoneyMixer(moneyMixer).moveToValidityCheckPhase();
    }

    // Get function 
    function getReferMixer() public view returns (address) {
        return referMixer;
    }

    function getMoneyMixer() public view returns (address) {
        return moneyMixer;
    }

    function getCurrentSigner() public view returns (address) {
        return roundInfo.signerInfo.currentSigner;
    }
}
