// All cryptographic primitives in one place.
// Anything that touches keys, randomness, or pad bytes goes through here.

import { argon2id } from 'hash-wasm';

// Convert between byte arrays and other formats.
export function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

export function bytesToBase64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

export function base64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

export function randomBytes(length) {
  const bytes = new Uint8Array(length);
  // crypto.getRandomValues is limited to 65,536 bytes per call by spec.
  // For larger pads we fill in 64 KB chunks. The OS CSPRNG remains the
  // entropy source — chunking does not weaken the result.
  const CHUNK = 65536;
  for (let offset = 0; offset < length; offset += CHUNK) {
    const view = bytes.subarray(offset, Math.min(offset + CHUNK, length));
    crypto.getRandomValues(view);
  }
  return bytes;
}

// SHA-256 of a Uint8Array.
export async function sha256(bytes) {
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return new Uint8Array(hash);
}

// Derive a 256-bit AES key from a passphrase using Argon2id.
// Salt must be 16 random bytes, generated once when the passphrase is created
// and stored alongside the encrypted pad.
//
// Parameters: t=3, m=64MB, p=1 — OWASP 2025 minimum for interactive use.
// Returns a CryptoKey usable with AES-GCM.
export async function deriveKey(passphrase, salt) {
  const rawHex = await argon2id({
    password: passphrase,
    salt: salt,
    parallelism: 1,
    iterations: 3,
    memorySize: 65536,    // KiB → 64 MB
    hashLength: 32,
    outputType: 'hex'
  });
  const rawBytes = hexToBytes(rawHex);
  return await crypto.subtle.importKey(
    'raw',
    rawBytes,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
}

// Encrypt arbitrary bytes with AES-256-GCM. Returns { ciphertext, iv }.
export async function aesEncrypt(key, plaintext) {
  const iv = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    plaintext
  );
  return { ciphertext: new Uint8Array(ciphertext), iv };
}

// Decrypt with AES-256-GCM. Throws if tag verification fails.
export async function aesDecrypt(key, ciphertext, iv) {
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );
  return new Uint8Array(plaintext);
}

// XOR two equal-length byte arrays. Used for OTP encryption/decryption.
// Throws if lengths mismatch — defensive against pad-misuse bugs.
export function xorBytes(a, b) {
  if (a.length !== b.length) {
    throw new Error(`xorBytes: length mismatch ${a.length} vs ${b.length}`);
  }
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

// Best-effort secure wipe of a Uint8Array.
// Note: JavaScript provides no real guarantee — V8 may have copied the buffer
// during GC. This zeros the visible buffer; the underlying memory hygiene
// is the platform's responsibility. Surfaced in About dialog for honesty.
export function wipeBytes(bytes) {
  crypto.getRandomValues(bytes); // overwrite with random first
  bytes.fill(0);                  // then zero
}