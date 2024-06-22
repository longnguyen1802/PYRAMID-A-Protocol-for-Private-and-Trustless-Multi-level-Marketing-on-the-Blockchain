import {getRandomBigInt, modPower} from './Math';

export function generateKeyPair(g: bigint, q: bigint, p: bigint): {pubKey: bigint; privKey: bigint} {
  const privKey: bigint = getRandomBigInt(q);
  const pubKey: bigint = modPower(g, privKey, p);
  return {pubKey, privKey};
}
