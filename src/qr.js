// QR sequence encoder/decoder for pad transfer.
// Format documented in the comments above each function.

import QRCode from 'qrcode';
import { sha256, hexToBytes, bytesToHex } from './crypto.js';

const MAGIC = new TextEncoder().encode('VEIL');
const VERSION = 0x01;
const HEADER_SIZE = 4 + 1 + 8 + 4 + 4 + 16 + 2; // = 39 bytes
const PAYLOAD_MAX = 800;

// Encode the entire pad as an array of chunks ready for QR rendering.
// padIdHex is 16 hex chars (8 bytes). padBytes is Uint8Array.
// Returns array of Uint8Array, each is one full QR payload.
export async function encodePadAsChunks(padIdHex, padBytes) {
  if (padIdHex.length !== 16) throw new Error('padId must be 16 hex chars (8 bytes)');
  const padIdBytes = hexToBytes(padIdHex);
  const totalChunks = Math.ceil(padBytes.length / PAYLOAD_MAX);
  if (totalChunks > 0xFFFFFFFF) throw new Error('pad too large');

  const chunks = [];
  let prevHash = new Uint8Array(16); // zero-filled for chunk 0

  for (let i = 0; i < totalChunks; i++) {
    const start = i * PAYLOAD_MAX;
    const end = Math.min(start + PAYLOAD_MAX, padBytes.length);
    const payload = padBytes.subarray(start, end);
    const payloadLen = payload.length;

    const chunk = new Uint8Array(HEADER_SIZE + payloadLen);
    let pos = 0;
    chunk.set(MAGIC, pos); pos += 4;
    chunk[pos] = VERSION; pos += 1;
    chunk.set(padIdBytes, pos); pos += 8;
    new DataView(chunk.buffer).setUint32(pos, totalChunks, false); pos += 4;
    new DataView(chunk.buffer).setUint32(pos, i, false); pos += 4;
    chunk.set(prevHash, pos); pos += 16;
    new DataView(chunk.buffer).setUint16(pos, payloadLen, false); pos += 2;
    chunk.set(payload, pos);

    chunks.push(chunk);

    // Compute hash of THIS payload to chain into the next chunk
    const fullHash = await sha256(payload);
    prevHash = fullHash.subarray(0, 16);
  }

  return chunks;
}

// Render a single chunk to a canvas as a QR code.
// chunkBytes: Uint8Array. canvas: HTMLCanvasElement.
export async function renderChunkToCanvas(chunkBytes, canvas, sizePx) {
  await QRCode.toCanvas(canvas, [{ data: chunkBytes, mode: 'byte' }], {
    errorCorrectionLevel: 'L',  // L = 7% recovery — smaller, denser data isn't a worry at 800B
    margin: 4,                  // wider quiet zone helps phone-to-phone scanning
    width: sizePx,
    color: {
      dark: '#000000',          // standard dark-on-light, the polarity all decoders expect
      light: '#ffffff'
    }
  });
}

// Parse a scanned QR payload back into a chunk record.
// Returns { padId, totalChunks, index, prevHash, payload } or throws.
// Used by the scanner on Day 4. Built today so the protocol is unified.
export function parseChunk(bytes) {
  if (bytes.length < HEADER_SIZE) throw new Error('chunk too short');
  for (let i = 0; i < 4; i++) {
    if (bytes[i] !== MAGIC[i]) throw new Error('not a Veil chunk (bad magic)');
  }
  if (bytes[4] !== VERSION) throw new Error(`unsupported chunk version ${bytes[4]}`);
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const padId = bytesToHex(bytes.subarray(5, 13));
  const totalChunks = dv.getUint32(13, false);
  const index = dv.getUint32(17, false);
  const prevHash = bytes.subarray(21, 37);
  const payloadLen = dv.getUint16(37, false);
  if (bytes.length !== HEADER_SIZE + payloadLen) {
    throw new Error(`chunk size mismatch: header says ${payloadLen}, total length ${bytes.length}`);
  }
  const payload = bytes.subarray(HEADER_SIZE, HEADER_SIZE + payloadLen);
  return { padId, totalChunks, index, prevHash, payload };
}

export const QR_FORMAT = { HEADER_SIZE, PAYLOAD_MAX };