// Pad persistence: encrypted at rest with the passphrase-derived key.
// File layout per pad: a single JSON file at Documents/veil/pads/<id>.veil
// containing salt, iv, ciphertext (the pad bytes), metadata, and offset.

import { Filesystem, Directory, Encoding } from '@capacitor/filesystem';
import { Preferences } from '@capacitor/preferences';
import {
  randomBytes, aesEncrypt, aesDecrypt, deriveKey,
  bytesToBase64, base64ToBytes, sha256, bytesToHex
} from './crypto.js';

const PAD_DIR = 'veil/pads';
const PAD_INDEX_KEY = 'veil.pad.index';

// Pad metadata stored in the encrypted file:
//   id:        random 16-byte hex string, the filename
//   name:      contact name, e.g. "Esther"
//   size:      total pad size in bytes
//   offset:    next available byte index. Starts at 0. Monotonic.
//   created:   ISO timestamp
//   role:      "alice" or "bob" — determines whether this device sends from
//              the start of the pad or from the middle. Set during handshake.
//              For one-device demo, role is "self".

async function ensureDir() {
  try {
    await Filesystem.mkdir({
      path: PAD_DIR,
      directory: Directory.Documents,
      recursive: true
    });
  } catch (err) {
    // already exists is fine
    if (!String(err.message).includes('exist')) throw err;
  }
}

// Generate a fresh pad. Returns the pad metadata including id.
// The actual pad bytes are encrypted and written to disk; they are NOT
// returned in memory after this call.
export async function createPad({ name, sizeBytes, passphrase, role = 'self' }) {
  await ensureDir();

  const id = bytesToHex(randomBytes(8)); // 16 hex chars
  const salt = randomBytes(16);
  const padBytes = randomBytes(sizeBytes);
  const key = await deriveKey(passphrase, salt);
  const { ciphertext, iv } = await aesEncrypt(key, padBytes);

  const metadata = {
    id,
    name,
    size: sizeBytes,
    offset: 0,
    created: new Date().toISOString(),
    role
  };

  const fileContent = JSON.stringify({
    version: 1,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(ciphertext),
    metadata
  });

  await Filesystem.writeFile({
    path: `${PAD_DIR}/${id}.veil`,
    data: fileContent,
    directory: Directory.Documents,
    encoding: Encoding.UTF8
  });

  // wipe the in-memory pad bytes
  padBytes.fill(0);

  await addToIndex(id);
  return metadata;
}

// Read a pad's metadata without decrypting the body.
// Cheap operation, used to render the pad library list.
export async function readPadMetadata(id) {
  const result = await Filesystem.readFile({
    path: `${PAD_DIR}/${id}.veil`,
    directory: Directory.Documents,
    encoding: Encoding.UTF8
  });
  const parsed = JSON.parse(result.data);
  return parsed.metadata;
}

// Decrypt and return the full pad bytes. Caller MUST wipe when done.
// Returns { padBytes, metadata, fileContent } so the caller can later
// rewrite the file with an updated offset.
export async function unlockPad(id, passphrase) {
  const result = await Filesystem.readFile({
    path: `${PAD_DIR}/${id}.veil`,
    directory: Directory.Documents,
    encoding: Encoding.UTF8
  });
  const parsed = JSON.parse(result.data);
  const salt = base64ToBytes(parsed.salt);
  const iv = base64ToBytes(parsed.iv);
  const ciphertext = base64ToBytes(parsed.ciphertext);

  const key = await deriveKey(passphrase, salt);
  const padBytes = await aesDecrypt(key, ciphertext, iv);
  return { padBytes, metadata: parsed.metadata, parsed };
}

// Re-encrypt and write the pad back with an updated offset.
// Used after sending or receiving a message to advance the consumed-byte pointer.
// IMPORTANT: This also overwrites the consumed bytes with zeros before re-encrypting,
// so even if the device is later compromised the spent pad material is gone.
export async function commitPadAdvance(id, padBytes, parsed, newOffset, passphrase) {
  if (newOffset < parsed.metadata.offset) {
    throw new Error('Offset cannot move backwards');
  }
  if (newOffset > parsed.metadata.size) {
    throw new Error('Offset exceeds pad size');
  }

  // Zero out the consumed range
  for (let i = parsed.metadata.offset; i < newOffset; i++) {
    padBytes[i] = 0;
  }

  const salt = base64ToBytes(parsed.salt);
  const key = await deriveKey(passphrase, salt);
  const { ciphertext, iv } = await aesEncrypt(key, padBytes);

  const updated = {
    version: 1,
    salt: parsed.salt,
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(ciphertext),
    metadata: { ...parsed.metadata, offset: newOffset }
  };

  await Filesystem.writeFile({
    path: `${PAD_DIR}/${id}.veil`,
    data: JSON.stringify(updated),
    directory: Directory.Documents,
    encoding: Encoding.UTF8
  });

  padBytes.fill(0);
}

// List all pad IDs known to the app.
export async function listPads() {
  const { value } = await Preferences.get({ key: PAD_INDEX_KEY });
  if (!value) return [];
  return JSON.parse(value);
}

async function addToIndex(id) {
  const ids = await listPads();
  if (!ids.includes(id)) {
    ids.push(id);
    await Preferences.set({ key: PAD_INDEX_KEY, value: JSON.stringify(ids) });
  }
}

export async function deletePad(id) {
  await Filesystem.deleteFile({
    path: `${PAD_DIR}/${id}.veil`,
    directory: Directory.Documents
  });
  const ids = await listPads();
  await Preferences.set({
    key: PAD_INDEX_KEY,
    value: JSON.stringify(ids.filter(x => x !== id))
  });
}

export async function importPad({ id, name, padBytes, passphrase }) {
  const existing = await listPads();
  if (existing.includes(id)) {
    throw new Error(`Pad with id ${id} already exists on this device. Refusing to overwrite — would desynchronize offsets with the sender.`);
  }

  await ensureDir();

  const salt = randomBytes(16);
  const key = await deriveKey(passphrase, salt);
  const { ciphertext, iv } = await aesEncrypt(key, padBytes);

  const metadata = {
    id,
    name,
    size: padBytes.length,
    offset: 0,
    created: new Date().toISOString(),
    role: 'imported'
  };

  const fileContent = JSON.stringify({
    version: 1,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(ciphertext),
    metadata
  });

  await Filesystem.writeFile({
    path: `${PAD_DIR}/${id}.veil`,
    data: fileContent,
    directory: Directory.Documents,
    encoding: Encoding.UTF8
  });

  padBytes.fill(0);

  await addToIndex(id);
  return metadata;
}

// Decrypt and return raw pad bytes for export. Caller MUST wipe when done.
// This intentionally does NOT advance any offset — exporting is read-only.
// The full pad is exported regardless of current offset, because the receiver
// needs the complete pad to be in sync with the sender.
//
// IMPORTANT: in the current single-pad-export model, this is called BEFORE
// any messages have been encrypted (offset still 0). If offset > 0, exporting
// the pad to a new device would still work but the new device's offset starts
// at 0 — the two would be out of sync. Day 4 receiver enforces "fresh import
// only" by refusing to overwrite an existing pad with the same id.
export async function exportPadBytes(id, passphrase) {
  const { padBytes, metadata, parsed } = await unlockPad(id, passphrase);
  return { padBytes, metadata, parsed };
}