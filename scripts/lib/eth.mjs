/*
 * Zero dependency Ethereum toolkit shared by the deploy script and the anvil
 * backed parity tests: secp256k1 key handling and RFC 6979 signing, RLP
 * encoding, legacy EIP-155 transaction signing, a minimal JSON-RPC client and
 * contract deploy/call helpers. Built on the repo's own keccak and ABI codecs
 * so the whole pipeline is auditable in one place.
 */

import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const K = require('../../src/keccak.js');
const A = require('../../src/abi.js');

// ---------------------------------------------------------------------------
// secp256k1
// ---------------------------------------------------------------------------

const FIELD_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const ORDER_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
const G = { x: GX, y: GY };

function mod(a, m) {
  const r = a % m;
  return r < 0n ? r + m : r;
}

function powMod(b, e, m) {
  let r = 1n;
  let x = mod(b, m);
  let k = e;
  while (k > 0n) {
    if (k & 1n) r = (r * x) % m;
    x = (x * x) % m;
    k >>= 1n;
  }
  return r;
}

function pointAdd(p, q) {
  if (p === null) return q;
  if (q === null) return p;
  if (p.x === q.x && mod(p.y + q.y, FIELD_P) === 0n) return null;
  let l;
  if (p.x === q.x && p.y === q.y) {
    if (p.y === 0n) return null;
    l = mod(3n * p.x * p.x * powMod(2n * p.y, FIELD_P - 2n, FIELD_P), FIELD_P);
  } else {
    l = mod((q.y - p.y) * powMod(q.x - p.x, FIELD_P - 2n, FIELD_P), FIELD_P);
  }
  const x = mod(l * l - p.x - q.x, FIELD_P);
  const y = mod(l * (p.x - x) - p.y, FIELD_P);
  return { x, y };
}

function pointMul(scalar, point) {
  let p = point || G;
  let n = mod(scalar, ORDER_N);
  let r = null;
  while (n > 0n) {
    if (n & 1n) r = pointAdd(r, p);
    p = pointAdd(p, p);
    n >>= 1n;
  }
  return r;
}

export function privateKeyToAddress(privKeyBigInt) {
  const pub = pointMul(privKeyBigInt);
  const pubBytes = new Uint8Array(64);
  writeUint256(pubBytes, 0, pub.x);
  writeUint256(pubBytes, 32, pub.y);
  return '0x' + K.bytesToHex(K.keccak256(pubBytes).slice(12));
}

export function isValidPrivateKey(k) {
  return k > 0n && k < ORDER_N;
}

async function hmacSha256(keyBytes, dataBytes) {
  const subtle = globalThis.crypto.subtle;
  const key = await subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', key, dataBytes));
}

function intTo32(v) {
  const out = new Uint8Array(32);
  writeUint256(out, 0, v);
  return out;
}

function writeUint256(buf, offset, value) {
  let v = BigInt(value);
  for (let i = 31; i >= 0; i--) {
    buf[offset + i] = Number(v & 0xffn);
    v >>= 8n;
  }
}

// RFC 6979 deterministic nonce generation, HMAC-SHA256 form.
async function deterministicK(privKey, msgHashBytes) {
  const x = intTo32(privKey);
  const z = intTo32(mod(BigInt('0x' + K.bytesToHex(msgHashBytes)), ORDER_N));
  let v = new Uint8Array(32).fill(1);
  let k = new Uint8Array(32).fill(0);
  k = await hmacSha256(k, K.concatBytes(v, new Uint8Array([0]), x, z));
  v = await hmacSha256(k, v);
  k = await hmacSha256(k, K.concatBytes(v, new Uint8Array([1]), x, z));
  v = await hmacSha256(k, v);
  for (;;) {
    v = await hmacSha256(k, v);
    const candidate = BigInt('0x' + K.bytesToHex(v));
    if (candidate >= 1n && candidate < ORDER_N) return candidate;
    k = await hmacSha256(k, K.concatBytes(v, new Uint8Array([0])));
    v = await hmacSha256(k, v);
  }
}

/*
 * Sign a 32 byte digest with a private key. Returns { r, s, recid } with the
 * low-s normalisation applied (EIP-2) and the recovery id adjusted to match.
 */
export async function signDigest(privKey, msgHashBytes) {
  const z = mod(BigInt('0x' + K.bytesToHex(msgHashBytes)), ORDER_N);
  const k = await deterministicK(privKey, msgHashBytes);
  const kg = pointMul(k);
  const r = mod(kg.x, ORDER_N);
  let s = mod(powMod(k, ORDER_N - 2n, ORDER_N) * (z + r * privKey), ORDER_N);
  let recid = Number(kg.y & 1n) | (kg.x >= ORDER_N ? 2 : 0);
  if (s > ORDER_N / 2n) {
    s = ORDER_N - s;
    recid ^= 1;
  }
  return { r, s, recid };
}

// ---------------------------------------------------------------------------
// RLP
// ---------------------------------------------------------------------------

export function rlpEncode(item) {
  if (Array.isArray(item)) {
    const payload = K.concatBytes(...item.map(rlpEncode));
    return K.concatBytes(rlpLength(payload.length, 0xc0), payload);
  }
  const bytes = typeof item === 'bigint' || typeof item === 'number'
    ? bigintToBytes(BigInt(item))
    : item;
  if (bytes.length === 1 && bytes[0] < 0x80) return bytes;
  return K.concatBytes(rlpLength(bytes.length, 0x80), bytes);
}

function rlpLength(len, offset) {
  if (len < 56) return new Uint8Array([offset + len]);
  const lenBytes = bigintToBytes(BigInt(len));
  return K.concatBytes(new Uint8Array([offset + 55 + lenBytes.length]), lenBytes);
}

function bigintToBytes(v) {
  if (v === 0n) return new Uint8Array(0);
  let h = v.toString(16);
  if (h.length % 2) h = '0' + h;
  return K.hexToBytes(h);
}

function hexField(hex) {
  let h = String(hex);
  if (h.startsWith('0x')) h = h.slice(2);
  if (h === '') return new Uint8Array(0);
  if (h.length % 2) h = '0' + h;
  return K.hexToBytes(h);
}

// ---------------------------------------------------------------------------
// Legacy EIP-155 transaction signing
// ---------------------------------------------------------------------------

/*
 * tx: { nonce, gasPrice, gasLimit, to (address or null for deploy),
 *       value, data ('0x' hex), chainId }
 * returns the raw signed transaction as '0x' hex.
 */
export async function signLegacyTransaction(privKey, tx) {
  const chainId = BigInt(tx.chainId);
  const base = [
    BigInt(tx.nonce),
    BigInt(tx.gasPrice),
    BigInt(tx.gasLimit),
    tx.to ? hexField(tx.to) : new Uint8Array(0),
    BigInt(tx.value || 0),
    hexField(tx.data || '0x')
  ];
  const signingPayload = rlpEncode([...base, chainId, 0n, 0n]);
  const digest = K.keccak256(signingPayload);
  const { r, s, recid } = await signDigest(privKey, digest);
  const v = chainId * 2n + 35n + BigInt(recid);
  const signed = rlpEncode([...base, v, r, s]);
  return { raw: '0x' + K.bytesToHex(signed), hash: '0x' + K.bytesToHex(K.keccak256(signed)), v, r, s };
}

// ---------------------------------------------------------------------------
// Minimal JSON-RPC client (POST, error unwrapped)
// ---------------------------------------------------------------------------

export class JsonRpc {
  constructor(url, opts) {
    this.url = url;
    this.fetchFn = (opts && opts.fetch) || fetch;
    this.id = 0;
  }

  async call(method, params) {
    const res = await this.fetchFn(this.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++this.id, method, params: params || [] })
    });
    if (!res.ok) throw new Error('RPC HTTP ' + res.status);
    const data = await res.json();
    if (data.error) {
      const e = new Error(data.error.message || 'RPC error');
      e.code = data.error.code;
      e.data = data.error.data;
      throw e;
    }
    return data.result;
  }

  chainId() { return this.call('eth_chainId').then((h) => Number(BigInt(h))); }
  blockNumber() { return this.call('eth_blockNumber').then((h) => Number(BigInt(h))); }
  gasPrice() { return this.call('eth_gasPrice').then((h) => BigInt(h)); }
  nonce(address) {
    return this.call('eth_getTransactionCount', [address, 'pending']).then((h) => BigInt(h));
  }
  balance(address) { return this.call('eth_getBalance', [address, 'latest']).then((h) => BigInt(h)); }
  ethCall(to, data) { return this.call('eth_call', [{ to, data }, 'latest']); }
  estimateGas(tx) { return this.call('eth_estimateGas', [tx]).then((h) => BigInt(h)); }
  sendRaw(rawTx) { return this.call('eth_sendRawTransaction', [rawTx]); }
  receipt(hash) { return this.call('eth_getTransactionReceipt', [hash]); }

  async waitForReceipt(hash, timeoutMs, pollMs) {
    const deadline = Date.now() + (timeoutMs || 120000);
    while (Date.now() < deadline) {
      const r = await this.receipt(hash);
      if (r) return r;
      await new Promise((res) => setTimeout(res, pollMs || 1500));
    }
    throw new Error('receipt timeout for ' + hash);
  }
}

// ---------------------------------------------------------------------------
// Deploy + call helpers
// ---------------------------------------------------------------------------

/*
 * Deploy bytecode with abi encoded constructor args appended. Returns
 * { address, txHash, receipt }.
 */
export async function deployContract(rpc, privKey, chainId, bytecode, constructorTypes, constructorArgs) {
  const deployer = privateKeyToAddress(privKey);
  const initData = bytecode + A.encodeArgs(constructorTypes || [], constructorArgs || []);
  const [nonce, gasPrice] = await Promise.all([rpc.nonce(deployer), rpc.gasPrice()]);
  let gasLimit;
  try {
    gasLimit = await rpc.estimateGas({ from: deployer, data: '0x' + initData.replace(/^0x/, '') });
    gasLimit = gasLimit + gasLimit / 5n;
  } catch {
    gasLimit = 4_000_000n;
  }
  const signed = await signLegacyTransaction(privKey, {
    nonce, gasPrice, gasLimit, to: null, value: 0n,
    data: '0x' + initData.replace(/^0x/, ''), chainId
  });
  const txHash = await rpc.sendRaw(signed.raw);
  const receipt = await rpc.waitForReceipt(txHash);
  if (receipt.status !== '0x1') throw new Error('deploy reverted: ' + txHash);
  return { address: receipt.contractAddress, txHash, receipt, deployer };
}

/*
 * Send a state changing call. Returns { txHash, receipt } and throws on a
 * reverted receipt so failures surface loudly in verification flows.
 */
export async function sendCall(rpc, privKey, chainId, to, signature, args) {
  const sender = privateKeyToAddress(privKey);
  const data = A.encodeCall(signature, args || []);
  const [nonce, gasPrice] = await Promise.all([rpc.nonce(sender), rpc.gasPrice()]);
  let gasLimit;
  try {
    gasLimit = await rpc.estimateGas({ from: sender, to, data });
    gasLimit = gasLimit + gasLimit / 4n;
  } catch (err) {
    const e = new Error('gas estimation failed for ' + signature + ': ' + err.message);
    e.cause = err;
    throw e;
  }
  const signed = await signLegacyTransaction(privKey, {
    nonce, gasPrice, gasLimit, to, value: 0n, data, chainId
  });
  const txHash = await rpc.sendRaw(signed.raw);
  const receipt = await rpc.waitForReceipt(txHash);
  if (receipt.status !== '0x1') {
    const e = new Error('call reverted: ' + signature + ' tx ' + txHash);
    e.txHash = txHash;
    throw e;
  }
  return { txHash, receipt };
}

export { K, A, mod, powMod, pointMul, pointAdd, G, ORDER_N, FIELD_P };
