import { base64 } from '../../vendor/@scure/base/index.js';

export const MAX_FILE_BYTES = 1024 ** 3;
export const CHUNK_BYTES = 12 * 1024;
export const MAX_MESSAGES = 2000;
export const HISTORY_BYTES = 8 * 1024 ** 2;
export const MAX_TEXT = 8000;
export const WINDOW_CHUNKS = 12;

export function requireAscii(value, label, min, max, printable = true) {
  if (typeof value !== 'string' || value.length < min || value.length > max ||
      !(printable ? /^[\x20-\x7e]*$/ : /^[\x00-\x7f]*$/).test(value)) {
    throw new Error(`${label} must contain ${min} to ${max} ${printable ? 'printable ' : ''}ASCII characters.`);
  }
  return value;
}
export function normalizeRoom(room) {
  const result = String(room).trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9_-]{1,63}$/.test(result)) {
    throw new Error('Use 2 to 64 lowercase letters, numbers, underscores or hyphens for the room.');
  }
  return result;
}
export function nonceResponse(nonce) {
  if (!/^[a-f0-9]{32}$/.test(nonce) || BigInt(`0x${nonce}`) === 0n) throw new Error('Invalid KDC challenge.');
  return (BigInt(`0x${nonce}`) - 1n).toString(16).padStart(32, '0');
}
export function toBase64(bytes) {
  return base64.encode(bytes);
}
export function fromBase64(value) {
  if (typeof value !== 'string' || value.length > CHUNK_BYTES * 4 / 3 + 4 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error('Invalid ASCII file chunk.');
  }
  try { return base64.decode(value); }
  catch { throw new Error('Invalid ASCII file chunk.'); }
}
export function validateOffer(file) {
  if (!file || !/^[a-f0-9]{32}$/.test(file.id) || !Number.isSafeInteger(file.size) ||
      file.size < 0 || file.size > MAX_FILE_BYTES) throw new Error('Invalid file offer or file exceeds 1 GiB.');
  requireAscii(file.name, 'File name', 1, 240);
  requireAscii(file.mime || 'application/octet-stream', 'File type', 1, 120);
  return { id: file.id, name: file.name, mime: file.mime || 'application/octet-stream', size: file.size };
}

export class FileAssembler {
  constructor(file) {
    this.file = validateOffer(file);
    this.chunks = [];
    this.nextIndex = 0;
    this.bytes = 0;
  }
  append(index, bytes) {
    const expected = Math.min(CHUNK_BYTES, this.file.size - this.bytes);
    if (index !== this.nextIndex || expected <= 0 || bytes.length !== expected) {
      throw new Error('File chunk order or size does not match its authenticated manifest.');
    }
    this.chunks.push(bytes);
    this.nextIndex++;
    this.bytes += bytes.length;
  }
  finish(size, chunks) {
    if (size !== this.file.size || this.bytes !== size || chunks !== this.nextIndex ||
        chunks !== Math.ceil(size / CHUNK_BYTES)) throw new Error('The file is incomplete.');
    const blob = new Blob(this.chunks, { type: 'application/octet-stream' });
    this.chunks = [];
    return blob;
  }
}

export class ReplayWindow {
  constructor() { this.high = -1; this.bits = 0n; }
  accept(sequence) {
    if (!Number.isSafeInteger(sequence) || sequence < 0) return false;
    if (sequence > this.high) {
      const delta = sequence - this.high;
      this.bits = delta >= 128 ? 1n : ((this.bits << BigInt(delta)) | 1n) & ((1n << 128n) - 1n);
      this.high = sequence;
      return true;
    }
    const distance = this.high - sequence;
    if (distance >= 128 || (this.bits & (1n << BigInt(distance))) !== 0n) return false;
    this.bits |= 1n << BigInt(distance);
    return true;
  }
}
