/*
 * Keccak-256 (Ethereum flavour, pad 0x01) and SHA-256 helpers.
 *
 * Pure JavaScript, zero dependencies. The keccak-f[1600] permutation runs on
 * twenty five 64-bit lanes held as BigInt values. SHA-256 delegates to
 * crypto.subtle, which exists in modern browsers and in Node 20+.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else {
    root.PQPG = root.PQPG || {};
    root.PQPG.keccak = api;
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const MASK64 = (1n << 64n) - 1n;
  const RATE = 136; // 1088 bit rate for keccak-256

  const RC = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an,
    0x8000000080008000n, 0x000000000000808bn, 0x0000000080000001n,
    0x8000000080008081n, 0x8000000000008009n, 0x000000000000008an,
    0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
    0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n,
    0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n,
    0x000000000000800an, 0x800000008000000an, 0x8000000080008081n,
    0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n
  ];

  // Rotation offsets r[x][y] flattened to index x + 5*y.
  const ROT = [
    0n, 1n, 62n, 28n, 27n,
    36n, 44n, 6n, 55n, 20n,
    3n, 10n, 43n, 25n, 39n,
    41n, 45n, 15n, 21n, 8n,
    18n, 2n, 61n, 56n, 14n
  ];

  function rotl(x, n) {
    n = n % 64n;
    return ((x << n) | (x >> (64n - n))) & MASK64;
  }

  function keccakF(s) {
    const b = new Array(25);
    for (let round = 0; round < 24; round++) {
      // theta
      const c = new Array(5);
      for (let x = 0; x < 5; x++) {
        c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
      }
      for (let x = 0; x < 5; x++) {
        const d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1n);
        for (let y = 0; y < 5; y++) s[x + 5 * y] ^= d;
      }
      // rho and pi
      for (let x = 0; x < 5; x++) {
        for (let y = 0; y < 5; y++) {
          b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(s[x + 5 * y], ROT[x + 5 * y]);
        }
      }
      // chi
      for (let y = 0; y < 5; y++) {
        for (let x = 0; x < 5; x++) {
          s[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y] & MASK64) & b[(x + 2) % 5 + 5 * y]);
        }
      }
      // iota
      s[0] ^= RC[round];
    }
  }

  function keccak256(bytes) {
    const s = new Array(25).fill(0n);
    let offset = 0;

    // Absorb whole rate blocks.
    while (offset + RATE <= bytes.length) {
      for (let i = 0; i < RATE; i++) {
        s[i >> 3] ^= BigInt(bytes[offset + i]) << BigInt((i & 7) * 8);
      }
      keccakF(s);
      offset += RATE;
    }

    // Final padded block, keccak domain byte 0x01.
    const block = new Uint8Array(RATE);
    block.set(bytes.subarray(offset));
    block[bytes.length - offset] = 0x01;
    block[RATE - 1] |= 0x80;
    for (let i = 0; i < RATE; i++) {
      s[i >> 3] ^= BigInt(block[i]) << BigInt((i & 7) * 8);
    }
    keccakF(s);

    // Squeeze 32 bytes.
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      out[i] = Number((s[i >> 3] >> BigInt((i & 7) * 8)) & 0xffn);
    }
    return out;
  }

  async function sha256(bytes) {
    const subtle = globalThis.crypto && globalThis.crypto.subtle;
    if (!subtle) throw new Error('crypto.subtle is unavailable');
    const digest = await subtle.digest('SHA-256', bytes);
    return new Uint8Array(digest);
  }

  // ---- byte helpers ----------------------------------------------------

  function utf8Bytes(str) {
    return new TextEncoder().encode(str);
  }

  function hexToBytes(hex) {
    let h = String(hex);
    if (h.startsWith('0x') || h.startsWith('0X')) h = h.slice(2);
    if (h.length % 2) h = '0' + h;
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
    return out;
  }

  function bytesToHex(bytes) {
    let out = '';
    for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
    return out;
  }

  function concatBytes() {
    const parts = Array.prototype.slice.call(arguments);
    let len = 0;
    for (const p of parts) len += p.length;
    const out = new Uint8Array(len);
    let at = 0;
    for (const p of parts) {
      out.set(p, at);
      at += p.length;
    }
    return out;
  }

  function keccak256Hex(input) {
    const bytes = typeof input === 'string' ? utf8Bytes(input) : input;
    return bytesToHex(keccak256(bytes));
  }

  function keccak256Hex0x(input) {
    return '0x' + keccak256Hex(input);
  }

  return {
    keccak256,
    keccak256Hex,
    keccak256Hex0x,
    sha256,
    utf8Bytes,
    hexToBytes,
    bytesToHex,
    concatBytes
  };
}));
