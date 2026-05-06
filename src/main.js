import {
  randomBytes, deriveKey, aesEncrypt, aesDecrypt, sha256,
  bytesToBase64, base64ToBytes, bytesToHex, hexToBytes,
  xorBytes, wipeBytes
} from './crypto.js';
import {
  createPad, listPads, readPadMetadata, unlockPad,
  commitPadAdvance, deletePad, exportPadBytes
} from './storage.js';
import { Preferences } from '@capacitor/preferences';
import { encodePadAsChunks, renderChunkToCanvas } from './qr.js';

// ----------------------------------------------------------------------------
// App state
// ----------------------------------------------------------------------------
// We keep a single module-level state object. No framework. Re-render on change.
const state = {
  screen: 'loading',     // loading | setup | unlock | library | create | pad | export  
  passphrase: null,      // held in memory only while unlocked
  selectedPadId: null,
  error: null,
  busy: false
};

const root = document.getElementById('app');

function render() {
  root.innerHTML = '';
  switch (state.screen) {
    case 'loading': renderLoading(); break;
    case 'setup': renderSetup(); break;
    case 'unlock': renderUnlock(); break;
    case 'library': renderLibrary(); break;
    case 'create': renderCreate(); break;
    case 'pad': renderPad(); break;
    case 'export': renderExport(); break;
    default: renderLoading();
  }
}

function navigate(screen, opts = {}) {
  state.screen = screen;
  state.error = null;
  if (opts.clearPassphrase) state.passphrase = null;
  if (opts.padId !== undefined) state.selectedPadId = opts.padId;
  render();
}

// ----------------------------------------------------------------------------
// Boot: decide whether this is first launch or returning user
// ----------------------------------------------------------------------------
const PASSPHRASE_VERIFIER_KEY = 'veil.passphrase.verifier';

async function boot() {
  const { value } = await Preferences.get({ key: PASSPHRASE_VERIFIER_KEY });
  if (value) {
    state.screen = 'unlock';
  } else {
    state.screen = 'setup';
  }
  render();
}

// ----------------------------------------------------------------------------
// Passphrase verifier
// ----------------------------------------------------------------------------
// We never store the passphrase. To check whether an entered passphrase is
// correct, we store: salt + AES-GCM(key=Argon2(passphrase, salt), plaintext=KNOWN_MARKER).
// At unlock time, we re-derive the key and try to decrypt. If GCM verifies,
// the passphrase is correct.
const KNOWN_MARKER = new TextEncoder().encode('veil-passphrase-marker-v1');

async function setPassphraseVerifier(passphrase) {
  const salt = randomBytes(16);
  const key = await deriveKey(passphrase, salt);
  const { ciphertext, iv } = await aesEncrypt(key, KNOWN_MARKER);
  await Preferences.set({
    key: PASSPHRASE_VERIFIER_KEY,
    value: JSON.stringify({
      salt: bytesToBase64(salt),
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(ciphertext)
    })
  });
}

async function verifyPassphrase(passphrase) {
  const { value } = await Preferences.get({ key: PASSPHRASE_VERIFIER_KEY });
  if (!value) return false;
  const parsed = JSON.parse(value);
  const salt = base64ToBytes(parsed.salt);
  const iv = base64ToBytes(parsed.iv);
  const ciphertext = base64ToBytes(parsed.ciphertext);
  try {
    const key = await deriveKey(passphrase, salt);
    const decrypted = await aesDecrypt(key, ciphertext, iv);
    const expected = KNOWN_MARKER;
    if (decrypted.length !== expected.length) return false;
    for (let i = 0; i < expected.length; i++) {
      if (decrypted[i] !== expected[i]) return false;
    }
    return true;
  } catch {
    return false;
  }
}

// ----------------------------------------------------------------------------
// Screens
// ----------------------------------------------------------------------------

function renderLoading() {
  root.innerHTML = `
    <div class="screen">
      <div class="eyebrow">Veil</div>
      <div class="hint">Loading…</div>
    </div>`;
}

function renderSetup() {
  root.innerHTML = `
    <div class="screen">
      <p class="eyebrow">First launch</p>
      <h1 class="title">Set a passphrase</h1>
      <p class="subtitle">This locks every pad on this device. There is no recovery if you forget it. Pick something memorable but long.</p>
      <div class="field">
        <label>Passphrase</label>
        <input id="pp1" type="password" autocomplete="new-password" placeholder="At least 12 characters" />
      </div>
      <div class="field">
        <label>Confirm</label>
        <input id="pp2" type="password" autocomplete="new-password" />
      </div>
      <button id="go" class="full">Lock the device</button>
      <div id="err" class="error"></div>
      <div id="busy" class="spinner"></div>
    </div>`;
  const go = document.getElementById('go');
  const err = document.getElementById('err');
  const busy = document.getElementById('busy');
  go.onclick = async () => {
    err.textContent = '';
    const p1 = document.getElementById('pp1').value;
    const p2 = document.getElementById('pp2').value;
    if (p1.length < 12) { err.textContent = 'Passphrase must be at least 12 characters.'; return; }
    if (p1 !== p2) { err.textContent = 'Passphrases do not match.'; return; }
    go.disabled = true;
    busy.textContent = 'Deriving key (1–2 seconds)…';
    try {
      await setPassphraseVerifier(p1);
      state.passphrase = p1;
      navigate('library');
    } catch (e) {
      err.textContent = `Setup failed: ${e.message}`;
      go.disabled = false;
      busy.textContent = '';
    }
  };
}

function renderUnlock() {
  root.innerHTML = `
    <div class="screen">
      <p class="eyebrow">Veil</p>
      <h1 class="title">Welcome back</h1>
      <p class="subtitle">Enter your passphrase to unlock pads.</p>
      <div class="field">
        <label>Passphrase</label>
        <input id="pp" type="password" autocomplete="current-password" />
      </div>
      <button id="go" class="full">Unlock</button>
      <div id="err" class="error"></div>
      <div id="busy" class="spinner"></div>
    </div>`;
  const go = document.getElementById('go');
  const err = document.getElementById('err');
  const busy = document.getElementById('busy');
  const pp = document.getElementById('pp');
  pp.focus();
  pp.addEventListener('keydown', e => { if (e.key === 'Enter') go.click(); });
  go.onclick = async () => {
    err.textContent = '';
    const value = pp.value;
    if (!value) return;
    go.disabled = true;
    busy.textContent = 'Verifying…';
    try {
      const ok = await verifyPassphrase(value);
      if (ok) {
        state.passphrase = value;
        navigate('library');
      } else {
        err.textContent = 'Wrong passphrase.';
        go.disabled = false;
        busy.textContent = '';
      }
    } catch (e) {
      err.textContent = `Verify failed: ${e.message}`;
      go.disabled = false;
      busy.textContent = '';
    }
  };
}

async function renderLibrary() {
  root.innerHTML = `
    <div class="screen">
      <p class="eyebrow">Pad library</p>
      <h1 class="title">Veil</h1>
      <p class="subtitle">Encrypted pads on this device.</p>
      <div id="list"></div>
      <div class="actions">
        <button id="new" class="full">+ New pad</button>
      </div>
    </div>`;
  document.getElementById('new').onclick = () => navigate('create');
  const list = document.getElementById('list');

  const ids = await listPads();
  if (ids.length === 0) {
    list.innerHTML = `<div class="empty">No pads yet. Create your first one.</div>`;
    return;
  }
  for (const id of ids) {
    try {
      const meta = await readPadMetadata(id);
      const used = meta.offset;
      const total = meta.size;
      const remaining = total - used;
      const pct = (used / total) * 100;
      const card = document.createElement('div');
      card.className = 'pad-card';
      card.innerHTML = `
        <div class="name">${escapeHtml(meta.name)}</div>
        <div class="meta">${formatBytes(remaining)} of ${formatBytes(total)} remaining · id ${meta.id.slice(0, 8)}</div>
        <div class="bar"><div style="width:${pct}%"></div></div>`;
      card.onclick = () => navigate('pad', { padId: id });
      list.appendChild(card);
    } catch (e) {
      const card = document.createElement('div');
      card.className = 'pad-card';
      card.innerHTML = `<div class="name">${id.slice(0, 8)}</div><div class="meta error">unreadable: ${escapeHtml(e.message)}</div>`;
      list.appendChild(card);
    }
  }
}

function renderCreate() {
  root.innerHTML = `
    <div class="screen">
      <div class="back" id="back">← Back</div>
      <p class="eyebrow">New pad</p>
      <h1 class="title">Generate</h1>
      <p class="subtitle">A fresh pad of true random bytes from the OS CSPRNG. Encrypted with your passphrase before it touches storage.</p>
      <div class="field">
        <label>Contact name</label>
        <input id="name" placeholder="e.g. Michael" />
      </div>
      <div class="field">
        <label>Pad size</label>
        <select id="size">
          <option value="262144">256 KB — about 5,000 short messages</option>
          <option value="1048576" selected>1 MB — about 20,000 short messages</option>
          <option value="4194304">4 MB — about 80,000 short messages</option>
        </select>
      </div>
      <button id="go" class="full">Generate pad</button>
      <div id="err" class="error"></div>
      <div id="busy" class="spinner"></div>
    </div>`;
  document.getElementById('back').onclick = () => navigate('library');
  const go = document.getElementById('go');
  const err = document.getElementById('err');
  const busy = document.getElementById('busy');
  go.onclick = async () => {
    err.textContent = '';
    const name = document.getElementById('name').value.trim();
    const size = parseInt(document.getElementById('size').value, 10);
    if (!name) { err.textContent = 'Name required.'; return; }
    go.disabled = true;
    busy.textContent = 'Generating entropy and encrypting…';
    try {
      await createPad({ name, sizeBytes: size, passphrase: state.passphrase });
      navigate('library');
    } catch (e) {
      err.textContent = `Failed: ${e.message}`;
      go.disabled = false;
      busy.textContent = '';
    }
  };
}

// Pad detail screen: encrypt and decrypt against the same pad on one device.
// This is the Day 2 round-trip proof. QR comes Day 3.
async function renderPad() {
  const id = state.selectedPadId;
  let meta;
  try {
    meta = await readPadMetadata(id);
  } catch (e) {
    root.innerHTML = `<div class="screen"><div class="error">Pad unreadable: ${escapeHtml(e.message)}</div></div>`;
    return;
  }
  const remaining = meta.size - meta.offset;
  root.innerHTML = `
    <div class="screen">
      <div class="back" id="back">← Library</div>
      <p class="eyebrow">${formatBytes(remaining)} remaining</p>
      <h1 class="title">${escapeHtml(meta.name)}</h1>
      <p class="subtitle">id ${meta.id} · offset ${meta.offset.toLocaleString()} / ${meta.size.toLocaleString()}</p>

      <div class="field">
        <label>Compose message</label>
        <textarea id="msg" placeholder="Type a short message"></textarea>
        <div class="hint">Each character consumes 1 byte of pad. UTF-8 multi-byte characters consume more.</div>
      </div>
      <button id="enc" class="full">Encrypt</button>
      <div id="enc-out" style="margin-top:1rem"></div>

      <div class="field" style="margin-top:2rem">
        <label>Decrypt ciphertext</label>
        <textarea id="ct" placeholder="Paste ciphertext (base64)"></textarea>
      </div>
      <button id="dec" class="full secondary">Decrypt</button>
      <div id="dec-out" style="margin-top:1rem"></div>

      <div class="actions" style="margin-top:2.5rem">
        <button id="exp" class="full secondary">Export to other device (QR)</button>
        <button id="del" class="full danger">Delete pad</button>
      </div>
      <div id="err" class="error"></div>
    </div>`;
  document.getElementById('back').onclick = () => navigate('library');

  const err = document.getElementById('err');

  document.getElementById('enc').onclick = async () => {
    err.textContent = '';
    const text = document.getElementById('msg').value;
    if (!text) { err.textContent = 'Message empty.'; return; }
    const plaintext = new TextEncoder().encode(text);
    if (plaintext.length > meta.size - meta.offset) {
      err.textContent = `Pad has ${meta.size - meta.offset} bytes left, message needs ${plaintext.length}.`;
      return;
    }
    document.getElementById('enc').disabled = true;
    try {
      const { padBytes, parsed } = await unlockPad(id, state.passphrase);
      const padSlice = padBytes.slice(meta.offset, meta.offset + plaintext.length);
      const ct = xorBytes(plaintext, padSlice);
      // header: 4-byte big-endian offset + 4-byte big-endian length
      const header = new Uint8Array(8);
      const dv = new DataView(header.buffer);
      dv.setUint32(0, meta.offset, false);
      dv.setUint32(4, plaintext.length, false);
      const packet = new Uint8Array(header.length + ct.length);
      packet.set(header, 0);
      packet.set(ct, header.length);
      const b64 = bytesToBase64(packet);

      const newOffset = meta.offset + plaintext.length;
      await commitPadAdvance(id, padBytes, parsed, newOffset, state.passphrase);
      // padBytes has been wiped inside commitPadAdvance
      wipeBytes(padSlice);
      wipeBytes(plaintext);

      document.getElementById('enc-out').innerHTML = `
        <label>Ciphertext (copy this to the other device)</label>
        <div class="cipher-output" id="ctout">${escapeHtml(b64)}</div>
        <div class="hint">${plaintext.length} pad bytes consumed. New offset: ${newOffset}.</div>`;
      // refresh meta from disk to reflect the new offset for any next encrypt on this screen
      meta = await readPadMetadata(id);
    } catch (e) {
      err.textContent = `Encrypt failed: ${e.message}`;
    } finally {
      document.getElementById('enc').disabled = false;
    }
  };

  document.getElementById('dec').onclick = async () => {
    err.textContent = '';
    const ctB64 = document.getElementById('ct').value.trim();
    if (!ctB64) { err.textContent = 'Paste ciphertext first.'; return; }
    let packet;
    try {
      packet = base64ToBytes(ctB64);
    } catch (e) {
      err.textContent = 'Not valid base64.'; return;
    }
    if (packet.length < 8) { err.textContent = 'Ciphertext too short.'; return; }
    const dv = new DataView(packet.buffer, packet.byteOffset, packet.byteLength);
    const offset = dv.getUint32(0, false);
    const length = dv.getUint32(4, false);
    if (packet.length !== 8 + length) { err.textContent = 'Length mismatch.'; return; }
    if (offset + length > meta.size) { err.textContent = 'Offset+length exceeds pad size.'; return; }
    const ct = packet.slice(8);
    document.getElementById('dec').disabled = true;
    try {
      const { padBytes, parsed } = await unlockPad(id, state.passphrase);
      const padSlice = padBytes.slice(offset, offset + length);
      // Note: in the one-device demo, the sender already advanced the offset
      // past `offset`. Reading at `offset` will return zeros (wiped). The
      // round-trip therefore must decrypt BEFORE the sender encrypts on the
      // same device. For the full two-device flow, Alice and Bob each have
      // their own copy of the pad with synchronized offsets.
      const plaintextBytes = xorBytes(ct, padSlice);
      const text = new TextDecoder().decode(plaintextBytes);

      // We do NOT advance offset on decrypt in this demo because the sender
      // already advanced it. Two-device flow: receiver advances after decrypt.
      wipeBytes(padBytes);
      wipeBytes(padSlice);

      document.getElementById('dec-out').innerHTML = `
        <label>Plaintext</label>
        <div class="cipher-output">${escapeHtml(text)}</div>`;
    } catch (e) {
      err.textContent = `Decrypt failed: ${e.message}`;
    } finally {
      document.getElementById('dec').disabled = false;
    }
  };

  document.getElementById('exp').onclick = () => {
    if (meta.offset > 0) {
      if (!confirm(`This pad already has ${meta.offset} bytes consumed. Exporting now will desynchronize with the recipient. Continue anyway?`)) return;
    }
    navigate('export', { padId: id });
  };
  document.getElementById('del').onclick = async () => {
    if (!confirm(`Delete "${meta.name}" permanently? The pad bytes are gone forever.`)) return;
    try {
      await deletePad(id);
      navigate('library');
    } catch (e) {
      err.textContent = `Delete failed: ${e.message}`;
    }
  };
}

// ----------------------------------------------------------------------------
// Export screen: animated QR sequence broadcasting the pad to a partner device.
// ----------------------------------------------------------------------------
async function renderExport() {
  const id = state.selectedPadId;
  let meta;
  try {
    meta = await readPadMetadata(id);
  } catch (e) {
    root.innerHTML = `<div class="screen"><div class="error">Pad unreadable: ${escapeHtml(e.message)}</div></div>`;
    return;
  }

  // Initial UI: confirm + start.
  root.innerHTML = `
    <div class="screen">
      <div class="back" id="back">← Cancel</div>
      <p class="eyebrow">Export</p>
      <h1 class="title">${escapeHtml(meta.name)}</h1>
      <p class="subtitle">Broadcast the pad to the recipient device as a sequence of QR codes. Their camera will scan them in order. Hold the phones still and aligned.</p>
      <div class="hint" style="margin-bottom:1.5rem">${formatBytes(meta.size)} of pad bytes · about ${Math.ceil(meta.size / 2200)} QR codes · ${(Math.ceil(meta.size / 2200) / 2).toFixed(0)} seconds at 2 codes/sec</div>
      <button id="start" class="full">Start broadcasting</button>
      <div id="err" class="error"></div>
      <div id="busy" class="spinner"></div>
    </div>`;

  document.getElementById('back').onclick = () => navigate('pad', { padId: id });
  const err = document.getElementById('err');
  const busy = document.getElementById('busy');

  document.getElementById('start').onclick = async () => {
    busy.textContent = 'Decrypting pad and chunking…';
    document.getElementById('start').disabled = true;
    let padBytes;
    let chunks;
    try {
      const exp = await exportPadBytes(id, state.passphrase);
      padBytes = exp.padBytes;
      chunks = await encodePadAsChunks(meta.id, padBytes);
    } catch (e) {
      err.textContent = `Export prep failed: ${e.message}`;
      busy.textContent = '';
      document.getElementById('start').disabled = false;
      return;
    }

    // Render the broadcasting UI.
    root.innerHTML = `
      <div class="screen">
        <div class="back" id="back2">← Stop</div>
        <p class="eyebrow" id="eyebrow">Broadcasting · 0 / ${chunks.length}</p>
        <h1 class="title" style="font-size:1.5rem">${escapeHtml(meta.name)}</h1>
        <div style="display:flex;justify-content:center;margin:1.5rem 0">
          <canvas id="qr" width="320" height="320" style="background:var(--bg);border:1px solid var(--border);border-radius:4px"></canvas>
        </div>
        <div class="bar"><div id="prog" style="width:0%"></div></div>
        <div class="actions">
          <div class="row">
            <button id="pause" class="secondary">Pause</button>
            <button id="slow" class="secondary">Half speed</button>
          </div>
        </div>
        <div class="hint" id="rateHint" style="margin-top:1rem">2 codes / second</div>
      </div>`;

    const canvas = document.getElementById('qr');
    const eyebrow = document.getElementById('eyebrow');
    const prog = document.getElementById('prog');
    const pauseBtn = document.getElementById('pause');
    const slowBtn = document.getElementById('slow');
    const rateHint = document.getElementById('rateHint');
    document.getElementById('back2').onclick = () => {
      stopped = true;
      // Wipe pad bytes immediately on cancel
      if (padBytes) wipeBytes(padBytes);
      navigate('pad', { padId: id });
    };

    let i = 0;
    let intervalMs = 500; // 2 per second
    let paused = false;
    let stopped = false;

    pauseBtn.onclick = () => {
      paused = !paused;
      pauseBtn.textContent = paused ? 'Resume' : 'Pause';
    };
    slowBtn.onclick = () => {
      intervalMs = intervalMs === 500 ? 1000 : 500;
      slowBtn.textContent = intervalMs === 500 ? 'Half speed' : 'Full speed';
      rateHint.textContent = intervalMs === 500 ? '2 codes / second' : '1 code / second';
    };

    // Pre-render first frame
    await renderChunkToCanvas(chunks[0], canvas, 320);
    eyebrow.textContent = `Broadcasting · 1 / ${chunks.length}`;
    prog.style.width = `${(1 / chunks.length) * 100}%`;
    i = 1;

    while (i < chunks.length && !stopped) {
      await sleep(intervalMs);
      if (stopped) break;
      if (paused) { i--; continue; } // re-loop without advancing
      try {
        await renderChunkToCanvas(chunks[i], canvas, 320);
        eyebrow.textContent = `Broadcasting · ${i + 1} / ${chunks.length}`;
        prog.style.width = `${((i + 1) / chunks.length) * 100}%`;
      } catch (e) {
        eyebrow.textContent = `Render failed at chunk ${i}: ${e.message}`;
        break;
      }
      i++;
    }

    if (!stopped && i >= chunks.length) {
      eyebrow.textContent = `Broadcast complete · ${chunks.length} / ${chunks.length}`;
      // Loop back to the start so a slow scanner can still complete.
      // The receiver knows total_chunks and ignores duplicates.
      eyebrow.textContent += ' · looping';
      i = 0;
      while (!stopped) {
        await sleep(intervalMs);
        if (stopped) break;
        if (paused) continue;
        await renderChunkToCanvas(chunks[i], canvas, 320);
        eyebrow.textContent = `Looping · ${i + 1} / ${chunks.length}`;
        i = (i + 1) % chunks.length;
      }
    }

    // Wipe on exit
    if (padBytes) wipeBytes(padBytes);
  };
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------
function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, ch => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[ch]));
}

// Boot
boot().catch(e => {
  root.innerHTML = `<div class="screen"><div class="error">Boot failed: ${escapeHtml(e.message)}</div></div>`;
});