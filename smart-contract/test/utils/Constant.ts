//export const p: bigint = BigInt('115792089237316195423570985008687907852837564279074904382605163141518161494337');
//export const q: bigint = BigInt('341948486974166000522343609283189');
//export const g: bigint = BigInt('3382179820063921351711459720945002840687054300606715993250688069077934439078');
export const p: bigint = BigInt('107');
export const q: bigint = BigInt('106');
export const g: bigint = BigInt('2');
export const numeParentFee: bigint = BigInt(1);
export const demoParentFee: bigint = BigInt(2);
export const protocolFee: bigint = BigInt(100);
export const joinFee: bigint = BigInt(100000);
export const signerDepositFee: bigint = BigInt(100000);
export const deploymenLength: number = 7 * 70; // 700 block a day
export const roundLong: number = 120;
export const referPhaseLength: number = 40;
export const moneyPhaseLength: number = 30;
export const networkUrls: {[key: string]: string} = {
  ganache: 'http://localhost:8545',
  ganachecli: 'http://localhost:7545',
};
