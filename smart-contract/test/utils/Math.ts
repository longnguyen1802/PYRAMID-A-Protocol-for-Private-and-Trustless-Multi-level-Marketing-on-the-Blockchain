import {ethers} from 'hardhat';
import {randomBytes} from 'crypto';
export function modPower(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result: bigint = BigInt(1);
  base = base % modulus;
  while (exponent > 0n) {
    if (exponent % 2n === 1n) {
      result = (result * base) % modulus;
    }
    exponent = exponent / 2n;
    base = (base * base) % modulus;
  }
  return result;
}

export function gcd(a: bigint, b: bigint): bigint {
  // Implement the Euclidean algorithm to find the GCD
  while (b !== 0n) {
    const temp: bigint = b;
    b = a % b;
    a = temp;
  }
  return a;
}

export function getRandomBigInt(max: bigint): bigint {
  return BigInt('0x' + randomBytes(32).toString('hex')) % max;
}

export function getRandomRelativePrime(max: bigint, moduloNumber: bigint): bigint {
  let number: bigint = getRandomBigInt(max-BigInt(1))+BigInt(1);
  let subMod: bigint = moduloNumber % number;
  while (gcd(number, subMod) !== 1n) {
    number = getRandomBigInt(max-BigInt(1))+BigInt(1);
    subMod = moduloNumber % number;
  }
  return number;
}
