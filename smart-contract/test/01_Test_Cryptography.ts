import {expect} from 'chai';
import {ethers} from 'hardhat';
import {Cryptography} from '../typechain-types';
import {getRandomRelativePrime, getRandomBigInt, modPower} from './utils/Math';
import {generateKeyPair} from './utils/KeyGen';
import {p, q, g} from './utils/Constant';

interface PartialBlindSignature {
  c: bigint;
  s: bigint;
  y: bigint;
  t: bigint;
}
describe('Cryptography', () => {
  let Cryptography: any; // Changed the type to any
  let cryptography: Cryptography;
  let Ms: bigint;
  let Md: bigint;
  let accounts: any;

  before(async () => {
    [, ...accounts] = await ethers.getSigners();
    Cryptography = await ethers.getContractFactory('Cryptography');
    Ms = getRandomBigInt(q);
    Md = getRandomBigInt(q);
    cryptography = await Cryptography.deploy(p, q, g, Ms, Md);
  });

  // describe('BlindSchnorr', () => {
  //   it('verifySchnoorSignature', async () => {
  //     const K: bigint = getRandomBigInt(q);
  //     const r: bigint = modPower(g, K, p);
  //     const alpha: bigint = getRandomBigInt(q);
  //     const beta: bigint = getRandomBigInt(q);
  //     const m: string = accounts[0].address;
  //     const {pubKey: puSignKey, privKey: prSignKey} = generateKeyPair(g, q, p);
  //     const [e0, e] = await cryptography.blindSignatureMessage(r, alpha, beta, puSignKey, m);
  //     const s: bigint = await cryptography.signBlindSignatureMessage(prSignKey, K, e);

  //     const [_, s0] = await cryptography.unblindBlindSignatureMessage(s, alpha, e0);
  //     expect(await cryptography.verifyBlindSignature(e0, s0, m, puSignKey)).to.be.equal(true);
  //   });
  // });

  // describe('AbeOkamoto Partial Blind', () => {
  //   it('verifyAbeOkamotoSignature', async () => {
  //     const prnonce: bigint = getRandomBigInt(q);

  //     const {pubKey: puSignKey, privKey: prSignKey} = generateKeyPair(g, q, p);

  //     const info: bigint = BigInt(100);
  //     const [a, b, z] = await cryptography.preparePartialBlindMessage(prnonce, info);
  //     const t1: bigint = getRandomBigInt(q);
  //     const t2: bigint = getRandomBigInt(q);
  //     const t3: bigint = getRandomBigInt(q);
  //     const t4: bigint = getRandomBigInt(q);
  //     const m: string = accounts[0].address;

  //     const e: bigint = await cryptography.partialBlindMessage(a, b, t1, t2, t3, t4, z, m, puSignKey);

  //     const [r, c]: bigint[] = await cryptography.signPartialBlind(prnonce, e, prSignKey);

  //     const [rho, omega, sigma, delta] = await cryptography.ublindPartialBlindMessage(t1, t2, t3, t4, r, c);

  //     expect(await cryptography.verifyPartialBlindMessage(puSignKey, z, m, rho, omega, sigma, delta)).to.be.equal(
  //       true,
  //     );
  //   });
  // });

  describe('Elgama', () => {
    it('verifyElgamaSignature', async () => {
      const {pubKey: puSignKey, privKey: prSignKey} = generateKeyPair(g, q, p);

      const k: bigint = getRandomRelativePrime(q, p - 1n);
      const m: bigint = getRandomBigInt(q);

      const [r, s]: bigint[] = await cryptography.generateElgamaSignature(k, m, prSignKey);
      expect(await cryptography.verifyElgamaSignature(m, r, s, puSignKey)).to.be.eq(true);
    });
  });

  describe('BlindSignature', () => {
    it('verifyBlindSignature', async () => {
      const {pubKey: puSignKey, privKey: prSignKey} = generateKeyPair(g, q, p);
      const a: bigint = getRandomRelativePrime(q, q);
      const y: bigint = getRandomRelativePrime(q, q);
      const [A, Y] = await cryptography.BSprepareNonce(a, y, puSignKey);
      const r1: bigint = getRandomRelativePrime(q, q);
      const r2: bigint = getRandomRelativePrime(q, q);
      const gamma: bigint = getRandomRelativePrime(q, q);
      const memberAddress: string = accounts[0].address;
      const [_c0, c] = await cryptography.BSblindMessage(r1, r2, gamma, A, Y, memberAddress);
      const s = await cryptography.BSsignBlindMessage(a, y, prSignKey, c);
      const [c0, s0, y0] = await cryptography.BSunblindBlindMessage(_c0, gamma, s, y, r1);
      expect(await cryptography.BSverifyBlindSignature(c0, s0, y0, puSignKey, memberAddress)).to.be.eq(true);
    });
  });
  describe('PartialBlindSignature', () => {
    it('verifyPartialBlindSignature', async () => {
      const {pubKey: puSignKey, privKey: prSignKey} = generateKeyPair(g, q, p);
      const info: bigint = getRandomRelativePrime(q, q);
      const a: bigint = getRandomRelativePrime(q, q);
      const y: bigint = getRandomRelativePrime(q, q);
      const t: bigint = getRandomRelativePrime(q, q);
      const [A, C] = await cryptography.PBSprepareNonce(a, y, t, info);
      const r1: bigint = getRandomRelativePrime(q, q);
      const r2: bigint = getRandomRelativePrime(q, q);
      const factor: bigint = getRandomRelativePrime(q, q);
      const gamma2: bigint = getRandomRelativePrime(q, q);
      const gamma1: bigint = factor * gamma2;
      const memberAddress: string = accounts[0].address;
      const [_c0, c] = await cryptography.PBSblindMessage(r1, r2, gamma1, gamma2, A, C, info, memberAddress);
      const s = await cryptography.PBSsignBlindMessage(a, y, prSignKey, c);
      const [c0, s0, y0, t0] = await cryptography.PBSunblindBlindMessage(_c0, gamma1, gamma2, s, y, r1, r2, t);
      expect(
        await cryptography.PBSverifyBlindSignature({c: c0, s: s0, y: y0, t: t0}, info, puSignKey, memberAddress),
      ).to.be.eq(true);
    });
  });
});
