// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

struct PartialBlindSignature{
  uint256 c;
  uint256 s;
  uint256 y;
  uint256 t;
}

struct PartialBlind {
  uint256 p;
  uint256 q;
  uint256 g;
  uint256 mS;
  uint256 mD;
}

struct Blind {
  uint256 g;
  uint256 p;
  uint256 q;
}

struct Elgama {
  uint256 p;
  uint256 g;
}

interface ICryptography {
  /**************************Blind Schnoor Function ***************************/
  function blindSignatureMessage(
    uint256 r,
    uint256 alpha,
    uint256 beta,
    uint256 y,
    address m
  ) external view returns (uint256, uint256);

  function signBlindSignatureMessage(
    uint256 prk,
    uint256 K,
    uint256 e
  ) external view returns (uint256);

  function unblindBlindSignatureMessage(
    uint256 s,
    uint256 alpha,
    uint256 e0
  ) external view returns (uint256, uint256);

  function verifyBlindSignature(
    uint256 e0,
    uint256 s0,
    address m,
    uint256 pk
  ) external returns (bool);

  function BSverifyBlindSignature(
    uint256 c,
    uint256 s,
    uint256 y,
    uint256 X,
    address memberAddress
  ) external view returns (bool);
  /**************************Partial Blind Function ***************************/
  function PBSverifyBlindSignature(
    PartialBlindSignature memory pbs,
    uint256 info,
    uint256 X,
    address memberAddress
  ) external view returns (bool);

  function preparePartialBlindMessage(
    uint256 u,
    uint256 info
  ) external view returns (uint256, uint256, uint256);

  function partialBlindMessage(
    uint256 a,
    uint256 b,
    uint256 t1,
    uint256 t2,
    uint256 t3,
    uint256 t4,
    uint256 z,
    address m,
    uint256 y
  ) external view returns (uint256);

  function signPartialBlind(
    uint256 u,
    uint256 e,
    uint256 x
  ) external view returns (uint256, uint256);

  function ublindPartialBlindMessage(
    uint256 t1,
    uint256 t2,
    uint256 t3,
    uint256 t4,
    uint256 r,
    uint256 c
  ) external view returns (uint256, uint256, uint256, uint256);

  function verifyPartialBlindMessage(
    uint256 y,
    uint256 z,
    address m,
    uint256 rho,
    uint256 omega,
    uint256 sigma,
    uint256 delta
  ) external returns (bool);

  /************************** Elgama ***************************/
  function verifyElgamaSignature(
    uint256 m,
    uint256 r,
    uint256 s,
    uint256 y
  ) external view returns (bool);
}
