// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import "../math/Math.sol";
import "../interfaces/ICryptography.sol";
import "hardhat/console.sol";
contract Cryptography is ICryptography {
  uint256 immutable p;
  uint256 immutable q;
  uint256 immutable g;
  Blind bl;
  PartialBlind pb;
  Elgama elgama;

  constructor(uint256 _p, uint256 _q, uint256 _g, uint256 _d, uint256 _s) {
    p = _p;
    q = _q;
    g = _g;
    bl = Blind(g, p, q);
    pb = PartialBlind(p, q, g, _d, _s);
    elgama = Elgama(p, g);
  }

  /**************************Blind Signature Function ***************************/
  function BSprepareNonce(uint256 a, uint256 y, uint256 X) public view returns (uint256, uint256) {
    uint256 A = Math.modExp(bl.g, a, bl.p);
    uint256 Y = Math.modExp(X, y, bl.p);
    return (A, Y);
  }
  function BSblindMessage(
    uint256 r1,
    uint256 r2,
    uint256 gamma,
    uint256 A,
    uint256 Y,
    address memberAddress
  ) public view returns (uint256, uint256) {
    uint256 Y0 = Math.modExp(Y, gamma, bl.p);
    uint256 A0 = mulmod(
      Math.modExp(bl.g, r1, bl.p),
      mulmod(Math.modExp(A, gamma, bl.p), Math.modExp(Y0, r2, bl.p), bl.p),
      bl.p
    );
    uint256 c0 = uint256(keccak256(abi.encode(A0, Y0, memberAddress))) % (bl.p - 1);
    uint256 c = c0 + r2;
    return (c0, c);
  }
  function BSsignBlindMessage(
    uint256 a,
    uint256 y,
    uint256 x,
    uint256 c
  ) public pure returns (uint256) {
    return a + c * x * y;
  }

  function BSunblindBlindMessage(
    uint256 c0,
    uint256 gamma,
    uint256 s,
    uint256 y,
    uint256 r1
  ) public pure returns (uint256, uint256, uint256) {
    uint256 s0 = gamma * s + r1;
    uint256 y0 = gamma * y;
    return (c0, s0, y0);
  }
  function BSverifyBlindSignature(
    uint256 c,
    uint256 s,
    uint256 y,
    uint256 X,
    address memberAddress
  ) public view returns (bool) {
    uint256 Y = Math.modExp(X, y, bl.p);
    uint256 A = mulmod(
      Math.modExp(bl.g, s, bl.p),
      Math.invMod(Math.modExp(Y, c, bl.p), bl.p),
      bl.p
    );
    return (c % (bl.p - 1) == uint256(keccak256(abi.encode(A, Y, memberAddress))) % (bl.p - 1));
  }

  function blindSignatureMessage(
    uint256 r,
    uint256 alpha,
    uint256 beta,
    uint256 pusign,
    address memberAddress
  ) public view returns (uint256, uint256) {
    uint256 r0 = mulmod(
      r,
      mulmod(
        Math.invMod(Math.modExp(bl.g, alpha, bl.p), bl.p),
        Math.invMod(Math.modExp(pusign, beta, bl.p), bl.p),
        bl.p
      ),
      bl.p
    );
    uint256 e0 = uint256(keccak256(abi.encode(memberAddress, r0))) % bl.p;
    uint256 e = (e0 + beta) % bl.p;
    return (e0, e);
  }

  function signBlindSignatureMessage(
    uint256 prsign,
    uint256 K,
    uint256 e
  ) public view returns (uint256) {
    return (K + bl.q - mulmod(prsign, e, bl.q)) % bl.q;
  }

  function unblindBlindSignatureMessage(
    uint256 s,
    uint256 alpha,
    uint256 e0
  ) public view returns (uint256, uint256) {
    uint256 s0 = (s + bl.q - alpha) % bl.q;
    return (e0, s0);
  }

  function verifyBlindSignature(
    uint256 e0,
    uint256 s0,
    address m,
    uint256 pusign
  ) external view returns (bool) {
    uint256 verifyFactor = mulmod(
      Math.modExp(bl.g, s0, bl.p),
      Math.modExp(pusign, e0, bl.p),
      bl.p
    );
    return ((e0 % bl.p) == uint256(keccak256(abi.encode(m, verifyFactor))) % bl.p);
  }
  /**************************Partial Blind Function ***************************/
  function PBSprepareNonce(
    uint256 a,
    uint256 y,
    uint256 t,
    uint256 info
  ) public view returns (uint256, uint256) {
    uint256 A = Math.modExp(bl.g, a, bl.p);
    uint256 Z = uint256(keccak256(abi.encode(info))) % bl.p;
    uint256 C = mulmod(Math.modExp(bl.g, t, bl.p), Math.modExp(Z, y, bl.p), bl.p);
    return (A, C);
  }
  function PBSblindMessage(
    uint256 r1,
    uint256 r2,
    uint256 gamma1,
    uint256 gamma2,
    uint256 A,
    uint256 C,
    uint256 info,
    address memberAddress
  ) public view returns (uint256, uint256) {
    uint256 Z = uint256(keccak256(abi.encode(info))) % bl.p;
    uint256 C0 = mulmod(Math.modExp(C, gamma1, bl.p), Math.modExp(g, r2, bl.p), bl.p);
    uint256 A0Comp1 = Math.modExp(bl.g, r1, bl.p);
    uint256 A0Comp2 = Math.modExp(A, gamma1 / gamma2, bl.p);
    uint256 A0 = mulmod(A0Comp1, A0Comp2, bl.p);
    uint256 c0 = uint256(keccak256(abi.encode(Z, A0, C0, memberAddress))) % (bl.p - 1);
    uint256 c = c0 * gamma2;
    return (c0, c);
  }
  function PBSsignBlindMessage(
    uint256 a,
    uint256 y,
    uint256 x,
    uint256 c
  ) public pure returns (uint256) {
    return a + c * x * y;
  }

  function PBSunblindBlindMessage(
    uint256 c0,
    uint256 gamma1,
    uint256 gamma2,
    uint256 s,
    uint256 y,
    uint256 r1,
    uint256 r2,
    uint256 t
  ) public pure returns (uint256, uint256, uint256, uint256) {
    uint256 s0 = (s * gamma1) / gamma2 + r1;
    uint256 y0 = gamma1 * y;
    uint256 t0 = gamma1 * t + r2;
    return (c0, s0, y0, t0);
  }
  function PBSverifyBlindSignature(
    PartialBlindSignature memory pbs,
    uint256 info,
    uint256 X,
    address memberAddress
  ) public view returns (bool) {
    uint256 Z = uint256(keccak256(abi.encode(info))) % pb.p;
    uint256 C = mulmod(Math.modExp(g, pbs.t, pb.p), Math.modExp(Z, pbs.y, pb.p), pb.p);
    uint256 A = mulmod(
      Math.modExp(pb.g, pbs.s, pb.p),
      Math.invMod(Math.modExp(X, pbs.c * pbs.y, pb.p), pb.p),
      pb.p
    );
    return pbs.c % (pb.p - 1) == uint256(keccak256(abi.encode(Z, A, C, memberAddress))) % (pb.p - 1);
  }

  function preparePartialBlindMessage(
    uint256 prnonce,
    uint256 info
  ) public view returns (uint256, uint256, uint256) {
    uint256 z = uint256(keccak256(abi.encode(info)));
    uint256 a = Math.modExp(pb.g, prnonce, pb.p);
    uint256 b = mulmod(Math.modExp(pb.g, pb.mS, pb.p), Math.modExp(z, pb.mD, pb.p), pb.p);
    return (a, b, z);
  }

  function partialBlindMessage(
    uint256 a,
    uint256 b,
    uint256 t1,
    uint256 t2,
    uint256 t3,
    uint256 t4,
    uint256 z,
    address m,
    uint256 pusign
  ) public view returns (uint256) {
    uint256 alpha = mulmod(
      a,
      mulmod(Math.modExp(pb.g, t1, pb.p), Math.modExp(pusign, t2, pb.p), pb.p),
      pb.p
    );
    uint256 beta = mulmod(
      b,
      mulmod(Math.modExp(pb.g, t3, pb.p), Math.modExp(z, t4, pb.p), pb.p),
      pb.p
    );
    uint256 theta = uint256(keccak256(abi.encode(alpha, beta, z, m)));
    return (theta + pb.q - ((t2 + t4) % pb.q)) % pb.q;
  }

  function signPartialBlind(
    uint256 prnonce,
    uint256 e,
    uint256 prsign
  ) public view returns (uint256, uint256) {
    uint256 c = (e + pb.q - (pb.mD % pb.q)) % pb.q;
    uint256 r = (prnonce + pb.q - (mulmod(c, prsign, pb.q) % pb.q)) % pb.q;
    return (r, c);
  }

  function ublindPartialBlindMessage(
    uint256 t1,
    uint256 t2,
    uint256 t3,
    uint256 t4,
    uint256 r,
    uint256 c
  ) public view returns (uint256, uint256, uint256, uint256) {
    uint256 rho = (r + (t1 % pb.q));
    uint256 omega = (c + (t2 % pb.q));
    uint256 sigma = (pb.mS + (t3 % pb.q));
    uint256 delta = (pb.mD + (t4 % pb.q));
    return (rho, omega, sigma, delta);
  }

  function verifyPartialBlindMessage(
    uint256 pusign,
    uint256 z,
    address m,
    uint256 rho,
    uint256 omega,
    uint256 sigma,
    uint256 delta
  ) public view returns (bool) {
    uint256 checkAlpha = mulmod(
      Math.modExp(pb.g, rho, pb.p),
      Math.modExp(pusign, omega, pb.p),
      pb.p
    );
    uint256 checkBeta = mulmod(Math.modExp(pb.g, sigma, pb.p), Math.modExp(z, delta, pb.p), pb.p);

    uint256 checkSig = uint256(keccak256(abi.encode(checkAlpha, checkBeta, z, m)));
    return ((omega + delta) % pb.q) == (checkSig % pb.q);
  }

  /************************** Elgama ***************************/
  function generateElgamaSignature(
    uint256 k,
    uint256 m,
    uint256 prkey
  ) public view returns (uint256, uint256) {
    uint256 r = Math.modExp(g, k, p);
    uint256 hashMessage = uint256(keccak256(abi.encode(m)));
    uint256 part = mulmod(prkey, r, p - 1) % (p - 1);
    uint256 s;
    if (hashMessage > part) {
      s = mulmod((hashMessage - part) % (p - 1), Math.invMod(k, p - 1), p - 1);
    } else {
      s = mulmod((p - 1 - part + hashMessage) % (p - 1), Math.invMod(k, p - 1), p - 1);
    }

    return (r, s);
  }
  /**
   *
   * @param m Message sign
   * @param r Part of signature
   * @param s Part of signature
   * @param pukey Public key of signer
   */
  function verifyElgamaSignature(
    uint256 m,
    uint256 r,
    uint256 s,
    uint256 pukey
  ) public view returns (bool) {
    uint256 computeVerify = mulmod(
      Math.modExp(r, s, elgama.p),
      Math.modExp(pukey, r, elgama.p),
      elgama.p
    );

    uint256 hashMessage = uint256(keccak256(abi.encode(m)));
    return (Math.modExp(elgama.g, hashMessage, elgama.p) == computeVerify);
  }
}
