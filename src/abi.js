/*
 * Minimal ABI codec for the static types used by PQPayGuardEscrow and ERC-20:
 * address, bool, uint8/64/256, bytes32, plus dynamic string decoding for
 * token symbol(). All encoding is 32 byte word based; there are no dynamic
 * argument types so head/tail packing is not needed.
 */
(function (root, factory) {
  const K = (typeof module === 'object' && module.exports)
    ? require('./keccak.js')
    : root.PQPG.keccak;
  const api = factory(K);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else {
    root.PQPG = root.PQPG || {};
    root.PQPG.abi = api;
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function (K) {
  'use strict';

  function typesOf(signature) {
    const open = signature.indexOf('(');
    const close = signature.lastIndexOf(')');
    if (open === -1 || close === -1) throw new TypeError('bad signature: ' + signature);
    const inner = signature.slice(open + 1, close).trim();
    return inner === '' ? [] : inner.split(',').map((t) => t.trim());
  }

  function selector(signature) {
    return K.bytesToHex(K.keccak256(K.utf8Bytes(signature)).slice(0, 4));
  }

  function encodeWord(type, value) {
    switch (type) {
      case 'address': {
        const a = String(value).toLowerCase();
        if (!/^0x[0-9a-f]{40}$/.test(a)) throw new TypeError('bad address: ' + value);
        return '0'.repeat(24) + a.slice(2);
      }
      case 'bool':
        return (value === true || value === 1n || value === 1 || value === 'true')
          ? '0'.repeat(63) + '1' : '0'.repeat(64);
      case 'bytes32': {
        const h = String(value).toLowerCase();
        if (!/^0x[0-9a-f]{64}$/.test(h)) throw new TypeError('bad bytes32: ' + value);
        return h.slice(2);
      }
      default: {
        const m = /^uint(\d+)$/.exec(type);
        if (!m) throw new TypeError('unsupported type: ' + type);
        const bits = Number(m[1]);
        const v = BigInt(value);
        if (v < 0n || v >= (1n << BigInt(bits))) {
          throw new RangeError(type + ' out of range: ' + value);
        }
        return v.toString(16).padStart(64, '0');
      }
    }
  }

  function isArrayType(type) {
    return /^(.+)\[\]$/.test(type);
  }

  function arrayBaseType(type) {
    const m = /^(.+)\[\]$/.exec(type);
    return m ? m[1] : null;
  }

  function encodeArray(type, value) {
    const base = arrayBaseType(type);
    if (!base) throw new TypeError('not an array type: ' + type);
    if (!Array.isArray(value)) throw new TypeError(type + ' expects a JavaScript array');
    if (!/^uint\d+$/.test(base)) throw new TypeError('unsupported array element type: ' + base);
    const len = value.length.toString(16).padStart(64, '0');
    return len + value.map((v) => encodeWord(base, v)).join('');
  }

  function encodeArgs(types, values) {
    if (types.length !== values.length) {
      throw new TypeError('arg count mismatch: ' + types.length + ' vs ' + values.length);
    }
    // ABI head/tail layout. Static words sit in the head; dynamic arrays are
    // represented by a byte offset in the head and a length-prefixed tail.
    const headSize = types.length * 32;
    let tailBytes = 0;
    const encodedTails = types.map((t, i) => {
      if (!isArrayType(t)) return null;
      const hex = encodeArray(t, values[i]);
      const out = { hex, offset: headSize + tailBytes };
      tailBytes += hex.length / 2;
      return out;
    });
    return types.map((t, i) => {
      if (!isArrayType(t)) return encodeWord(t, values[i]);
      return encodedTails[i].offset.toString(16).padStart(64, '0');
    }).join('') + encodedTails.map((x) => x ? x.hex : '').join('');
  }

  // Returns 0x prefixed calldata for a signature like 'release(uint256)'.
  function encodeCall(signature, values) {
    return '0x' + selector(signature) + encodeArgs(typesOf(signature), values || []);
  }

  function wordAt(hex, index) {
    let h = String(hex);
    if (h.startsWith('0x')) h = h.slice(2);
    const start = index * 64;
    if (start + 64 > h.length) throw new RangeError('word ' + index + ' out of bounds');
    return h.slice(start, start + 64);
  }

  function decodeWord(type, hex, index) {
    const w = wordAt(hex, index);
    switch (type) {
      case 'address':
        return '0x' + w.slice(24);
      case 'bool':
        return BigInt('0x' + w) !== 0n;
      case 'bytes32':
        return '0x' + w;
      case 'string': {
        // value at index is an offset to length + data
        const off = Number(BigInt('0x' + w)) * 2;
        const len = Number(BigInt('0x' + hex.slice(2).slice(off, off + 64)));
        const raw = hex.slice(2).slice(off + 64, off + 64 + len * 2);
        let s = '';
        for (let i = 0; i < raw.length; i += 2) s += String.fromCharCode(parseInt(raw.substr(i, 2), 16));
        return s;
      }
      default: {
        if (/^uint\d+\[\]$/.test(type)) {
          const base = arrayBaseType(type);
          const offWords = Number(BigInt('0x' + w)) / 32;
          const len = Number(decodeWord('uint256', hex, offWords));
          const out = [];
          for (let j = 0; j < len; j++) out.push(decodeWord(base, hex, offWords + 1 + j));
          return out;
        }
        if (!/^uint\d+$/.test(type)) throw new TypeError('unsupported type: ' + type);
        return BigInt('0x' + w);
      }
    }
  }

  // Decode an abi.encode(...) blob of static types into a values array.
  function decodeArgs(types, hex) {
    return types.map((t, i) => decodeWord(t, hex, i));
  }

  function decodeCallArgs(signature, calldata) {
    const cd = String(calldata);
    if ('0x' + selector(signature) !== cd.slice(0, 10).toLowerCase()) {
      throw new TypeError('selector mismatch for ' + signature);
    }
    return decodeArgs(typesOf(signature), '0x' + cd.slice(10));
  }

  return {
    typesOf,
    selector,
    encodeWord,
    isArrayType,
    arrayBaseType,
    encodeArray,
    encodeArgs,
    encodeCall,
    decodeWord,
    decodeArgs,
    decodeCallArgs
  };
}));
