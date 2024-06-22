import {ethers} from 'hardhat';
import {Signer} from 'ethers';
import {getRandomBigInt} from '../utils/Math';
import {generateKeyPair} from '../utils/KeyGen';
import {Cryptography, Protocol, MemberAccount, ReferMixer, MoneyMixer} from '../../typechain-types';
import {
  p,
  q,
  g,
  numeParentFee,
  demoParentFee,
  protocolFee,
  joinFee,
  signerDepositFee,
  deploymenLength,
  roundLong,
  referPhaseLength,
  moneyPhaseLength,
} from '../utils/Constant';

export function generateMemberAccountParams(
  g: bigint,
  q: bigint,
  p: bigint,
): {
  pusign: bigint;
  prsign: bigint;
  purk: bigint;
  prrk: bigint;
  pusk: bigint;
  prsk: bigint;
  punonce: bigint;
  prnonce: bigint;
} {
  const {pubKey: pusign, privKey: prsign} = generateKeyPair(g, q, p);
  const {pubKey: purk, privKey: prrk} = generateKeyPair(g, q, p);
  const {pubKey: pusk, privKey: prsk} = generateKeyPair(g, q, p);
  const {pubKey: punonce, privKey: prnonce} = generateKeyPair(g, q, p);
  return {pusign, prsign, purk, prrk, pusk, prsk, punonce, prnonce};
}

async function deployCryptography(): Promise<Cryptography> {
  const Cryptography = await ethers.getContractFactory('Cryptography');
  const Ms: bigint = getRandomBigInt(q);
  const Md: bigint = getRandomBigInt(q);
  const cryptography: Cryptography = await Cryptography.deploy(p, q, g, Ms, Md);
  await cryptography.waitForDeployment();
  return cryptography;
}

async function deployProtocol(): Promise<Protocol> {
  const Protocol = await ethers.getContractFactory('Protocol');
  const protocol: Protocol = await Protocol.deploy(
    numeParentFee,
    demoParentFee,
    protocolFee,
    joinFee,
    signerDepositFee,
    deploymenLength,
    roundLong,
  );
  await protocol.waitForDeployment();
  return protocol;
}

async function deployReferMixer(protocolAddress: string, cryptographyAddress: string): Promise<ReferMixer> {
  const ReferMixer = await ethers.getContractFactory('ReferMixer');
  const referMixer: ReferMixer = await ReferMixer.deploy(protocolAddress, cryptographyAddress, referPhaseLength);
  await referMixer.waitForDeployment();
  return referMixer;
}

async function deployMoneyMixer(protocolAddress: string, cryptographyAddress: string): Promise<MoneyMixer> {
  const MoneyMixer = await ethers.getContractFactory('MoneyMixer');
  const moneyMixer: MoneyMixer = await MoneyMixer.deploy(protocolAddress, cryptographyAddress, moneyPhaseLength);
  await moneyMixer.waitForDeployment();
  return moneyMixer;
}

export async function deployMemberAccount(
  protocolAddress: string,
  cryptographyAddress: string,
  pubKey: bigint,
  sendKey: bigint,
  receiveKey: bigint,
  signNonce: bigint,
  user: Signer,
): Promise<MemberAccount> {
  const MemberAccount = await ethers.getContractFactory('MemberAccount');
  const account: MemberAccount = await MemberAccount.connect(user).deploy(
    protocolAddress,
    cryptographyAddress,
    pubKey,
    sendKey,
    receiveKey,
    signNonce,
    signerDepositFee,
    protocolFee,
    joinFee,
  );
  await account.waitForDeployment();
  return account;
}

export async function deployAll(): Promise<{
  _cryptography: Cryptography;
  _protocol: Protocol;
  _referMixer: ReferMixer;
  _moneyMixer: MoneyMixer;
}> {
  const _cryptography: Cryptography = await deployCryptography();
  const _protocol: Protocol = await deployProtocol();
  const _referMixer: ReferMixer = await deployReferMixer(
    await _protocol.getAddress(),
    await _cryptography.getAddress(),
  );
  const _moneyMixer: MoneyMixer = await deployMoneyMixer(
    await _protocol.getAddress(),
    await _cryptography.getAddress(),
  );
  await _protocol.setUpMixer(await _moneyMixer.getAddress(), await _referMixer.getAddress());
  return {_cryptography, _protocol, _referMixer, _moneyMixer};
}
