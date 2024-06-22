import {expect} from 'chai';
import {ethers} from 'hardhat';
import {Signer} from 'ethers';
import {Cryptography, MemberAccount, Protocol, ReferMixer, MoneyMixer} from '../typechain-types';
import {ProtocolParams, setupProtocol, setUpInitialMemberAndStart, AccountParams} from './helpers/setup';
import {getRandomBigInt, getRandomRelativePrime, modPower} from './utils/Math';
import {generateElgamaSignature} from './utils/SignatureGen';
import {deployMemberAccount, generateMemberAccountParams} from './helpers/deploy';
import {
  p,
  q,
  g,
  protocolFee,
  joinFee,
  referPhaseLength,
  moneyPhaseLength,
  signerDepositFee,
  roundLong,
} from './utils/Constant';
import {advanceBlockTo, getCurrentBlockNumber} from './utils/Time';

describe('MoneyWorkflow', () => {
  // Protocol params
  let params: ProtocolParams;

  let protocol: Protocol;
  let cryptography: Cryptography;
  let referMixer: ReferMixer;
  let moneyMixer: MoneyMixer;
  let account1: MemberAccount;
  let account2: MemberAccount;
  let account3: MemberAccount;
  let account4: MemberAccount;
  let ac1params: AccountParams;
  let ac2params: AccountParams;
  let ac3params: AccountParams;
  let ac4params: AccountParams;
  let user1: Signer;
  let user2: Signer;
  let user3: Signer;
  let user4: Signer;
  // For refer
  // For refer test
  let referA: bigint;
  let referY: bigint;
  let referR1: bigint;
  let referR2: bigint;
  let referGamma: bigint;
  let referC: bigint;
  let referC0: bigint;
  let A: bigint;
  let Y: bigint;
  let referPuNonce: bigint;
  //  For money test
  let moneyRno: bigint;
  let moneyMoney: bigint;
  let moneyInfo: bigint;
  let moneya: bigint;
  let moneyy: bigint;
  let moneyt: bigint;
  let moneyA: bigint;
  let moneyC: bigint;
  let moneyR1: bigint;
  let moneyR2: bigint;
  let moneyFactor: bigint;
  let moneyGamma1: bigint;
  let moneyGamma2: bigint;
  let moneyc: bigint;
  let moneyc0: bigint;

  let t1: bigint;
  let t2: bigint;
  let t3: bigint;
  let t4: bigint;
  let info: bigint;
  let z: bigint;
  let e: bigint;
  let r: bigint;
  before(async () => {
    params = await setupProtocol();
    await setUpInitialMemberAndStart(params);
    cryptography = params.cryptography;
    protocol = params.protocol;
    referMixer = params.referMixer;
    moneyMixer = params.moneyMixer;
    account1 = params.account1;
    account2 = params.account2;
    account3 = params.account3;
    ac1params = params.ac1params;
    ac2params = params.ac2params;
    ac3params = params.ac3params;
    user1 = params.user1;
    user2 = params.user2;
    user3 = params.user3;
    user4 = params.user4;
    // Refer Set up
    referPuNonce = getRandomBigInt(params.q);
    referA = getRandomRelativePrime(params.q, params.q);
    referY = getRandomRelativePrime(params.q, params.q);
    referR1 = getRandomRelativePrime(params.q, params.q);
    referR2 = getRandomRelativePrime(params.q, params.q);
    referGamma = getRandomRelativePrime(params.q, params.q);
    // Money Set up
    moneyRno = BigInt(1);
    moneyMoney = joinFee;
    const Moneyencoded = ethers.AbiCoder.defaultAbiCoder().encode(
      ['uint256', 'uint256'],
      [moneyMoney, moneyRno],
    );
    const MoneyhashMes = ethers.keccak256(Moneyencoded);
    moneyInfo = BigInt(MoneyhashMes);
    moneya = getRandomRelativePrime(q, q);
    moneyy = getRandomRelativePrime(q, q);
    moneyt = getRandomRelativePrime(q, q);
    moneyA = getRandomRelativePrime(q, q);
    moneyC = getRandomRelativePrime(q, q);
    moneyR1 = getRandomRelativePrime(q, q);
    moneyR2 = getRandomRelativePrime(q, q);
    moneyFactor = getRandomRelativePrime(q, q);
    moneyGamma2 = getRandomRelativePrime(q, q);
    moneyGamma1 = moneyFactor * moneyGamma2;
    info = joinFee;
    e = getRandomRelativePrime(q, q);
    // Deploy account4
    ac4params = generateMemberAccountParams(params.g, params.q, params.p);
    account4 = await deployMemberAccount(
      await params.protocol.getAddress(),
      await params.cryptography.getAddress(),
      ac4params.pusign,
      ac4params.pusk,
      ac4params.purk,
      ac4params.punonce,
      params.user4,
    );
    // Let make account 3 refer account 4 first
  });
  describe('Test MoneyWorkflow', () => {
    it('startRequestRefer', async () => {
      // Let user3 try to refer user4
      // Generate message
      const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
        ['address', 'uint256'],
        [await account3.getAddress(), referPuNonce],
      );
      const hashMes = ethers.keccak256(encoded);
      const actualMessage = BigInt(hashMes);
      const {r: rSig1, s: sSig1} = await generateElgamaSignature(cryptography, actualMessage, ac1params.prrk, p, q);
      await account1.connect(user1).startRequestRefer(await account3.getAddress(), referPuNonce, rSig1, sSig1);
      expect(await referMixer.referIdentify(await account3.getAddress(), referPuNonce)).to.be.eq(true);
    });
    it('noncegenerate', async () => {
      const [_A, _Y] = await cryptography.BSprepareNonce(referA, referY, ac1params.pusign);
      A = _A;
      Y = _Y;
    });
    it('sendReferRequest', async () => {
      const [_c0, _c] = await cryptography.BSblindMessage(
        referR1,
        referR2,
        referGamma,
        A,
        Y,
        await account4.getAddress(),
      );
      referC0 = _c0;
      referC = _c;
      // Generate message
      const encoded = ethers.AbiCoder.defaultAbiCoder().encode(['uint256', 'uint256'], [referPuNonce, referC]);
      const hashMes = ethers.keccak256(encoded);
      const actualMessage = BigInt(hashMes);
      const {r: rSig, s: sSig} = await generateElgamaSignature(cryptography, actualMessage, ac3params.prrk, p, q);
      await account3.connect(user3).sendReferRequest(referPuNonce, referC, rSig, sSig);
      const getC = await referMixer.referMessage(referPuNonce);
      expect(getC === referC).to.be.eq(true);
    });
    it('signReferRequest', async () => {
      let targetBlockNumber = (await getCurrentBlockNumber()) + referPhaseLength;
      await advanceBlockTo(targetBlockNumber);
      await protocol.startSignPhaseForReferMixer();
      const s = await cryptography.BSsignBlindMessage(referA, referY, ac1params.prsign, referC);
      // Start sign
      const encoded = ethers.AbiCoder.defaultAbiCoder().encode(['uint256', 'uint256'], [referPuNonce, s]);
      const hashMes = ethers.keccak256(encoded);
      const actualMessage = BigInt(hashMes);
      const {r: rSig, s: sSig} = await generateElgamaSignature(cryptography, actualMessage, ac1params.prrk, p, q);
      await account1.connect(user1).signReferRequest(referPuNonce, s, rSig, sSig);
      const referSig = await referMixer.referSignature(referPuNonce);
      expect(referSig === s).to.be.eq(true);
    });
    it('onBoardMember', async () => {
      let targetBlockNumber = (await getCurrentBlockNumber()) + referPhaseLength;
      await advanceBlockTo(targetBlockNumber);
      await protocol.startOnboardPhaseForReferMixer();
      const referSig = await referMixer.referSignature(referPuNonce);
      const [_c0, _s0, _y0] = await cryptography.BSunblindBlindMessage(referC0, referGamma, referSig, referY, referR1);
      // Start sign
      const encoded = ethers.AbiCoder.defaultAbiCoder().encode(['uint256', 'uint256', 'uint256'], [_c0, _s0, _y0]);
      const hashMes = ethers.keccak256(encoded);
      const actualMessage = BigInt(hashMes);
      const {r: rSig, s: sSig} = await generateElgamaSignature(cryptography, actualMessage, ac4params.prrk, p, q);

      await account4.connect(params.user4).onBoard(_c0, _s0, _y0, rSig, sSig, {value: protocolFee + joinFee});
      expect(await protocol.members(await account4.getAddress())).to.be.eq(true);
    });

    it('validityCheck for Refer', async () => {
      let targetBlockNumber = (await getCurrentBlockNumber()) + referPhaseLength;
      await advanceBlockTo(targetBlockNumber);
      await protocol.startValidityCheckPhaseForReferMixer();
      await protocol.connect(user1).referValidityCheck();
    });

    it('endRound', async () => {
      await account1.connect(user1).bidSigner({value: signerDepositFee});
      let targetBlockNumber = (await getCurrentBlockNumber()) + moneyPhaseLength;
      await advanceBlockTo(targetBlockNumber);
      await protocol.startSignPhaseForMoneyMixer();
      targetBlockNumber = (await getCurrentBlockNumber()) + moneyPhaseLength;
      await advanceBlockTo(targetBlockNumber);
      await protocol.startReceivePhaseForMoneyMixer();
      targetBlockNumber = (await getCurrentBlockNumber()) + moneyPhaseLength;
      await advanceBlockTo(targetBlockNumber);
      await protocol.startValidityCheckPhaseForMoneyMixer();
      targetBlockNumber = (await getCurrentBlockNumber()) + roundLong;
      await advanceBlockTo(targetBlockNumber);
      await protocol.endRound();
      await protocol.startNewRound();
    });

    it('nonceGeneration', async() =>{
      const Moneyencoded = ethers.AbiCoder.defaultAbiCoder().encode(
        ['uint256', 'uint256'],
        [moneyMoney, moneyRno],
      );
      const MoneyhashMes = ethers.keccak256(Moneyencoded);
      moneyInfo = BigInt(MoneyhashMes);
      const [_A,_C] = await cryptography.PBSprepareNonce(moneya,moneyy,moneyt,moneyInfo);
      moneyA = _A;
      moneyC = _C;
    });
    it('sendTransaction', async () => {
      // Send from account4 to account3
      const [_c0,_c] = await cryptography.PBSblindMessage(moneyR1,moneyR2,moneyGamma1,moneyGamma2,moneyA,moneyC,moneyInfo,account3.getAddress());
      moneyc0 = _c0;
      moneyc = _c;

      let index = BigInt(1);

      // Start sign
      const encoded = ethers.AbiCoder.defaultAbiCoder().encode(['uint256', 'uint256'], [index, moneyc]);
      const hashMes = ethers.keccak256(encoded);
      const actualMessage = BigInt(hashMes);
      const {r: rSig, s: sSig} = await generateElgamaSignature(cryptography, actualMessage, ac4params.prsk, p, q);
      await account4.connect(user4).sendTransaction(index, moneyc, rSig, sSig);
      let getIndex = await moneyMixer.distributeMoneyMessage(account4.getAddress(), moneyc);
      expect(getIndex === index).to.be.eq(true);
    });
    it('signTransaction', async () => {
      let targetBlockNumber = (await getCurrentBlockNumber()) + moneyPhaseLength;
      await advanceBlockTo(targetBlockNumber);
      await protocol.startSignPhaseForMoneyMixer();

      let s = await cryptography.PBSsignBlindMessage(moneya, moneyy, ac1params.prsign,moneyc);

      // Start sign
      const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
        ['address', 'uint256', 'uint256'],
        [await account4.getAddress(), moneyc, s],
      );
      const hashMes = ethers.keccak256(encoded);
      const actualMessage = BigInt(hashMes);
      const {r: rSig, s: sSig} = await generateElgamaSignature(cryptography, actualMessage, ac1params.prrk, p, q);
      await account1.connect(user1).signTransaction(account4.getAddress(), moneyc, s, rSig, sSig);
      let getSig = await moneyMixer.distributeMoneySignature(account4.getAddress(), moneyc);
      expect(getSig === s).to.be.eq(true);
    });
    it('receiveTransaction', async () => {
      let targetBlockNumber = (await getCurrentBlockNumber()) + moneyPhaseLength;
      await advanceBlockTo(targetBlockNumber);
      await protocol.startReceivePhaseForMoneyMixer();

      let getSig = await moneyMixer.distributeMoneySignature(account4.getAddress(), moneyc);

      const [c0,s0,y0,t0] = await cryptography.PBSunblindBlindMessage(moneyc0,moneyGamma1,moneyGamma2,getSig,moneyy,moneyR1,moneyR2,moneyt);
      // Start sign
      const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
        ['uint256','uint256', 'uint256', 'uint256', 'uint256', 'uint256'],
        [moneyMoney,moneyRno, c0, s0, y0, t0],
      );
      const hashMes = ethers.keccak256(encoded);
      const actualMessage = BigInt(hashMes);
      const {r: rSig, s: sSig} = await generateElgamaSignature(cryptography, actualMessage, ac3params.prrk, p, q);
      await account3.connect(user3).receiveTransaction(moneyMoney,moneyRno,c0,s0,y0,t0, rSig, sSig);
      let moneyRev = await moneyMixer.receiveTransactionConfirm(account3.getAddress());
      expect(moneyRev === info / BigInt(2)).to.be.eq(true);
    });
    it('moneyValidityCheck', async () => {
      let targetBlockNumber = (await getCurrentBlockNumber()) + moneyPhaseLength;
      await advanceBlockTo(targetBlockNumber);
      await protocol.startValidityCheckPhaseForMoneyMixer();
      await protocol.connect(user1).moneyValidityCheck();
    });
  });
});
