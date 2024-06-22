import {getRandomRelativePrime} from './Math';
import {Cryptography} from '../../typechain-types';
export async function generateElgamaSignature(
  cryptography: Cryptography,
  message: bigint,
  prikey: bigint,
  p: bigint,
  q: bigint,
) {
  const nonce = getRandomRelativePrime(q, p - BigInt(1));
  const [r, s] = await cryptography.generateElgamaSignature(nonce, message, prikey);
  return {r, s};
}
