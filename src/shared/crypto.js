import { sha256 } from '../../vendor/@noble/hashes/sha2.js';
import { pbkdf2 } from '../../vendor/@noble/hashes/pbkdf2.js';
import { base64 } from '../../vendor/@scure/base/index.js';

const EMPTY = new Uint8Array(0);
const MAX_CACHE_SIZE = 16;
const keyCache = new Map();
const decoder = new TextDecoder('utf-8', { fatal: true });

function requireBytes(value, name = 'Input') {
  if (!(value instanceof Uint8Array)) throw new TypeError(`${name} must be a Uint8Array.`);
  return value;
}

function requireString(value, name = 'Input') {
  if (typeof value !== 'string') throw new TypeError(`${name} must be a string.`);
  return value;
}

export function asciiBytes(text) {
  requireString(text);
  const result = new Uint8Array(text.length);
  for (let index = 0; index < text.length; index += 1) {
    const value = text.charCodeAt(index);
    if (value > 127) throw new Error('Only ASCII characters are supported.');
    result[index] = value;
  }
  return result;
}

export function utf8Text(value) {
  return decoder.decode(requireBytes(value));
}

export function bytesToHex(value) {
  requireBytes(value);
  const parts = new Array(value.length);
  for (let index = 0; index < value.length; index += 1) parts[index] = HEX[value[index]];
  return parts.join('');
}

const HEX = Array.from({ length: 256 }, (_, index) => index.toString(16).padStart(2, '0'));

export function hexToBytes(text) {
  requireString(text, 'Hex input');
  if (text.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(text)) {
    throw new Error('Hex input must contain complete hexadecimal byte pairs.');
  }
  const result = new Uint8Array(text.length / 2);
  for (let index = 0; index < result.length; index += 1) {
    result[index] = Number.parseInt(text.slice(index * 2, index * 2 + 2), 16);
  }
  return result;
}

export function randomBytes(length) {
  if (!Number.isSafeInteger(length) || length < 0 || length > 0x7fffffff) {
    throw new RangeError('Random byte length is invalid.');
  }
  if (!globalThis.crypto?.getRandomValues) throw new Error('Secure system randomness is unavailable.');
  const result = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += 65536) {
    globalThis.crypto.getRandomValues(result.subarray(offset, Math.min(length, offset + 65536)));
  }
  return result;
}

export function randomId() {
  return bytesToHex(randomBytes(16));
}

export function randomAsciiKey() {
  return base64.encode(randomBytes(24));
}

export function validateKey(key) {
  requireString(key, 'Key');
  if (!/^[\x20-\x7e]{32}$/.test(key)) {
    throw new Error('The AES-256 key must contain exactly 32 printable ASCII characters.');
  }
  return key;
}

export function encodeJson(value) {
  const json = JSON.stringify(value);
  if (typeof json !== 'string') throw new TypeError('The value cannot be represented as JSON.');
  return asciiBytes(json.replace(/[\u007f-\uffff]/g, (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`));
}

export function decodeJson(value) {
  return JSON.parse(utf8Text(value), (key, item) => {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      throw new Error('Unsafe JSON property name.');
    }
    return item;
  });
}

function normalizedRoom(room) {
  const normalized = requireString(room, 'Room name').normalize('NFKC').trim().toLowerCase();
  if (!normalized || normalized.length > 128) throw new Error('Room names must contain 1 to 128 characters.');
  return normalized;
}

export function deriveRoomKey(secret, room, mode, iterations = 210000) {
  if (!requireString(secret, 'Shared secret').length) throw new Error('A shared secret is required.');
  if (!Number.isSafeInteger(iterations) || iterations < 1 || iterations > 10000000) {
    throw new RangeError('PBKDF2 iterations must be between 1 and 10000000.');
  }
  const salt = encodeJson(['aes-channel', 'room-key', 1, requireString(mode, 'Mode'), normalizedRoom(room)]);
  const derived = pbkdf2(sha256, asciiBytes(secret), salt, { c: iterations, dkLen: 24 });
  return base64.encode(derived);
}

export function roomId(room, mode, keyMode) {
  return bytesToHex(sha256(encodeJson(['aes-channel', 'room-id', 1, requireString(mode, 'Mode'), requireString(keyMode, 'Key mode'), normalizedRoom(room)])));
}

export function fingerprint(key) {
  return bytesToHex(sha256(asciiBytes(validateKey(key))).subarray(0, 8));
}

const SBOX = new Uint8Array([
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]);
const DOUBLE = Uint8Array.from({ length: 256 }, (_, value) => ((value << 1) ^ (value & 0x80 ? 0x11b : 0)) & 255);

function expandedKey(key) {
  requireBytes(key, 'AES key');
  if (![16, 24, 32].includes(key.length)) throw new Error('AES keys must contain 16, 24, or 32 bytes.');
  const cacheId = bytesToHex(key);
  const existing = keyCache.get(cacheId);
  if (existing) return existing;
  const rounds = key.length / 4 + 6;
  const schedule = new Uint8Array(16 * (rounds + 1));
  schedule.set(key);
  let written = key.length;
  let rcon = 1;
  const temp = new Uint8Array(4);
  while (written < schedule.length) {
    temp.set(schedule.subarray(written - 4, written));
    if (written % key.length === 0) {
      const first = temp[0];
      temp[0] = SBOX[temp[1]] ^ rcon;
      temp[1] = SBOX[temp[2]];
      temp[2] = SBOX[temp[3]];
      temp[3] = SBOX[first];
      rcon = DOUBLE[rcon];
    } else if (key.length === 32 && written % key.length === 16) {
      for (let index = 0; index < 4; index += 1) temp[index] = SBOX[temp[index]];
    }
    for (let index = 0; index < 4; index += 1, written += 1) {
      schedule[written] = schedule[written - key.length] ^ temp[index];
    }
  }
  const entry = { schedule, rounds, ghashTable: null };
  if (keyCache.size >= MAX_CACHE_SIZE) keyCache.delete(keyCache.keys().next().value);
  keyCache.set(cacheId, entry);
  return entry;
}

function encryptBlockInto(expanded, input, output, state) {
  const { schedule, rounds } = expanded;
  for (let index = 0; index < 16; index += 1) state[index] = input[index] ^ schedule[index];
  for (let round = 1; round <= rounds; round += 1) {
    for (let index = 0; index < 16; index += 1) state[index] = SBOX[state[index]];
    let temporary = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temporary;
    temporary = state[2]; state[2] = state[10]; state[10] = temporary;
    temporary = state[6]; state[6] = state[14]; state[14] = temporary;
    temporary = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = temporary;
    if (round !== rounds) {
      for (let column = 0; column < 16; column += 4) {
        const a = state[column]; const b = state[column + 1];
        const c = state[column + 2]; const d = state[column + 3];
        const sum = a ^ b ^ c ^ d;
        state[column] ^= sum ^ DOUBLE[a ^ b];
        state[column + 1] ^= sum ^ DOUBLE[b ^ c];
        state[column + 2] ^= sum ^ DOUBLE[c ^ d];
        state[column + 3] ^= sum ^ DOUBLE[d ^ a];
      }
    }
    for (let index = 0; index < 16; index += 1) state[index] ^= schedule[round * 16 + index];
  }
  output.set(state);
}

export function aesEncryptBlock(keyBytes, block16) {
  requireBytes(block16, 'AES block');
  if (block16.length !== 16) throw new Error('AES operates on exactly 16-byte blocks.');
  const result = new Uint8Array(16);
  encryptBlockInto(expandedKey(keyBytes), block16, result, new Uint8Array(16));
  return result;
}

function writeWord(bytes, offset, value) {
  bytes[offset] = value >>> 24;
  bytes[offset + 1] = value >>> 16;
  bytes[offset + 2] = value >>> 8;
  bytes[offset + 3] = value;
}

function readWord(bytes, offset) {
  return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
}

function getGhashTable(expanded) {
  if (expanded.ghashTable) return expanded.ghashTable;
  const h = new Uint8Array(16);
  encryptBlockInto(expanded, h, h, new Uint8Array(16));
  const basis = new Uint32Array(128 * 4);
  let a = readWord(h, 0); let b = readWord(h, 4);
  let c = readWord(h, 8); let d = readWord(h, 12);
  for (let bit = 0; bit < 128; bit += 1) {
    basis.set([a, b, c, d], bit * 4);
    const low = d & 1;
    d = ((d >>> 1) | (c << 31)) >>> 0;
    c = ((c >>> 1) | (b << 31)) >>> 0;
    b = ((b >>> 1) | (a << 31)) >>> 0;
    a = ((a >>> 1) ^ (low ? 0xe1000000 : 0)) >>> 0;
  }

  const table = new Uint32Array(16 * 256 * 4);
  for (let position = 0; position < 16; position += 1) {
    const base = position * 1024;
    for (let value = 1; value < 256; value += 1) {
      const lowest = value & -value;
      const previous = base + (value ^ lowest) * 4;
      const power = (position * 8 + 7 - (31 - Math.clz32(lowest))) * 4;
      const target = base + value * 4;
      for (let word = 0; word < 4; word += 1) table[target + word] = table[previous + word] ^ basis[power + word];
    }
  }
  expanded.ghashTable = table;
  return table;
}

function ghashBlock(accumulator, block, offset, length, table) {
  let a = 0; let b = 0; let c = 0; let d = 0;
  for (let position = 0; position < 16; position += 1) {
    const word = accumulator[position >>> 2];
    const previous = (word >>> (24 - (position & 3) * 8)) & 255;
    const byte = previous ^ (position < length ? block[offset + position] : 0);
    const index = position * 1024 + byte * 4;
    a ^= table[index]; b ^= table[index + 1];
    c ^= table[index + 2]; d ^= table[index + 3];
  }
  accumulator[0] = a; accumulator[1] = b; accumulator[2] = c; accumulator[3] = d;
}

function ghash(expanded, aad, ciphertext) {
  const table = getGhashTable(expanded);
  const accumulator = new Uint32Array(4);
  for (const value of [aad, ciphertext]) {
    for (let offset = 0; offset < value.length; offset += 16) {
      ghashBlock(accumulator, value, offset, Math.min(16, value.length - offset), table);
    }
  }
  
  const lengths = new Uint8Array(16);
  const view = new DataView(lengths.buffer);
  view.setBigUint64(0, BigInt(aad.length) * 8n);
  view.setBigUint64(8, BigInt(ciphertext.length) * 8n);
  ghashBlock(accumulator, lengths, 0, 16, table);
  const result = new Uint8Array(16);
  for (let word = 0; word < 4; word += 1) writeWord(result, word * 4, accumulator[word]);
  return result;
}

function validateGcm(iv, value, aad) {
  requireBytes(iv, 'GCM IV');
  requireBytes(value);
  requireBytes(aad, 'Additional authenticated data');
  if (iv.length !== 12) throw new Error('GCM requires a 12-byte (96-bit) IV.');
  if (value.length > 0xfffffffe * 16) throw new Error('This message exceeds the GCM counter limit.');
}

function counterCrypt(expanded, iv, value) {
  const counter = new Uint8Array(16);
  counter.set(iv);
  const result = new Uint8Array(value.length);
  const stream = new Uint8Array(16);
  const state = new Uint8Array(16);
  let count = 1;
  for (let offset = 0; offset < value.length; offset += 16) {
    count = (count + 1) >>> 0;
    writeWord(counter, 12, count);
    encryptBlockInto(expanded, counter, stream, state);
    const length = Math.min(16, value.length - offset);
    for (let index = 0; index < length; index += 1) result[offset + index] = value[offset + index] ^ stream[index];
  }
  return result;
}

function authenticationTag(expanded, iv, ciphertext, aad) {
  const initialCounter = new Uint8Array(16);
  initialCounter.set(iv);
  initialCounter[15] = 1;
  const mask = new Uint8Array(16);
  encryptBlockInto(expanded, initialCounter, mask, new Uint8Array(16));
  const tag = ghash(expanded, aad, ciphertext);
  for (let index = 0; index < 16; index += 1) tag[index] ^= mask[index];
  return tag;
}

export function gcmEncrypt(keyBytes, iv12, plaintextBytes, aadBytes = EMPTY) {
  validateGcm(iv12, plaintextBytes, aadBytes);
  const expanded = expandedKey(keyBytes);
  const ciphertext = counterCrypt(expanded, iv12, plaintextBytes);
  return { ciphertext, tag: authenticationTag(expanded, iv12, ciphertext, aadBytes) };
}

export function gcmDecrypt(keyBytes, iv12, ciphertextBytes, tag16, aadBytes = EMPTY) {
  validateGcm(iv12, ciphertextBytes, aadBytes);
  requireBytes(tag16, 'GCM authentication tag');
  if (tag16.length !== 16) throw new Error('GCM requires a complete 16-byte authentication tag.');
  const expanded = expandedKey(keyBytes);
  const expected = authenticationTag(expanded, iv12, ciphertextBytes, aadBytes);
  let difference = 0;
  for (let index = 0; index < 16; index += 1) difference |= expected[index] ^ tag16[index];
  if (difference !== 0) throw new Error('Authentication failed. The key, ciphertext, IV, tag, or associated data is incorrect.');
  return counterCrypt(expanded, iv12, ciphertextBytes);
}

export function seal(keyString, plaintextBytes, aadString = '') {
  const key = asciiBytes(validateKey(keyString));
  const iv = randomBytes(12);
  const { ciphertext, tag } = gcmEncrypt(key, iv, plaintextBytes, asciiBytes(aadString));
  return { v: 1, iv: bytesToHex(iv), ciphertext: bytesToHex(ciphertext), tag: bytesToHex(tag) };
}

export function open(keyString, envelope, aadString = '') {
  validateKey(keyString);
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope) || envelope.v !== 1) {
    throw new Error('Unsupported encrypted envelope.');
  }
  if (typeof envelope.iv !== 'string' || envelope.iv.length !== 24 ||
      typeof envelope.tag !== 'string' || envelope.tag.length !== 32 ||
      typeof envelope.ciphertext !== 'string') throw new Error('Malformed encrypted envelope.');
  return gcmDecrypt(asciiBytes(keyString), hexToBytes(envelope.iv), hexToBytes(envelope.ciphertext), hexToBytes(envelope.tag), asciiBytes(aadString));
}
