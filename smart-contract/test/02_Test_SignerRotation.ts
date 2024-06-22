import {expect} from 'chai';
import {ethers} from 'hardhat';
import {Signer} from 'ethers';
import {Cryptography, MemberAccount, Protocol, ReferMixer, MoneyMixer} from '../typechain-types';
import {ProtocolParams, setupProtocol, setUpInitialMemberAndStart} from './helpers/setup';
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

describe('SignerRotation', () => {
  // Protocol contracts and accounts
  let protocol: Protocol;
  let cryptography: Cryptography;
  let referMixer: ReferMixer;
  let moneyMixer: MoneyMixer;
  let account1: MemberAccount;
  let account2: MemberAccount;
  let account3: MemberAccount;
  let user1: Signer;
  let user2: Signer;
  let user3: Signer;

  before(async () => {
    let params: ProtocolParams = await setupProtocol();
    await setUpInitialMemberAndStart(params);
    cryptography = params.cryptography;
    protocol = params.protocol;
    referMixer = params.referMixer;
    moneyMixer = params.moneyMixer;
    account1 = params.account1;
    account2 = params.account2;
    account3 = params.account3;
    user1 = params.user1;
    user2 = params.user2;
    user3 = params.user3;
  });

  describe('BidSigner', () => {
    it('bidForNextSigner', async () => {
      // Account 3 bids for the next signer
      await account3.connect(user3).bidSigner({value: signerDepositFee});
    });

    it('claimRefundSigner', async () => {
      // Claim refund for account 3
      const accountBalanceBefore: bigint = await ethers.provider.getBalance(await account3.getAddress());
      await account2.connect(user2).bidSigner({value: signerDepositFee});
      await account3.connect(user3).claimRefundSigner();
      const accountBalanceAfter: bigint = await ethers.provider.getBalance(await account3.getAddress());
      //expect((accountBalanceAfter- accountBalanceBefore).eq(signerDepositFee)).to.be.true;
    });
  });
});
