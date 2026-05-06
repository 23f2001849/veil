import './style.css';
import {
  randomBytes, deriveKey, aesEncrypt, aesDecrypt, sha256,
  bytesToBase64, base64ToBytes, bytesToHex, hexToBytes,
  xorBytes, wipeBytes
} from './crypto.js';
import {
  createPad, listPads, readPadMetadata, unlockPad,
  commitPadAdvance, deletePad, exportPadBytes, importPad
} from './storage.js';
import { Preferences } from '@capacitor/preferences';
import { encodePadAsChunks, renderChunkToCanvas } from './qr.js';
import { startScanning, ReceptionSession, parseChunk } from './scanner.js';
import { App } from '@capacitor/app';

// ----------------------------------------------------------------------------
// App state
// ----------------------------------------------------------------------------
const state = {
  screen: 'loading',     // loading | setup | unlock | library | create | pad | export | receive | about
  passphrase: null,
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
    case 'receive': renderReceive(); break;
    case 'about': renderAbout(); break;
    default: renderLoading();
  }
}

function navigate(screen, opts = {}) {
  state.screen = screen;
  state.error = null;
  if (opts.clearPassphrase) state.passphrase = null;
  if (opts.padId !== undefined) state.selectedPadId = opts.padId;
  // Restart the idle timer on every navigation.
  resetIdleTimer();
  render();
}

// ----------------------------------------------------------------------------
// Boot
// ----------------------------------------------------------------------------
const PASSPHRASE_VERIFIER_KEY = 'veil.passphrase.verifier';

// ----------------------------------------------------------------------------
// Auto-lock
// ----------------------------------------------------------------------------
// Two timers:
//   - idle: clears the passphrase after N minutes of no user interaction
//   - background: clears the passphrase after N seconds in background
//
// "Cleared" means state.passphrase = null and the screen jumps to unlock.
// Encrypted pads on disk are unaffected; the user re-enters the passphrase.

const IDLE_TIMEOUT_MS = 5 * 60 * 1000;       // 5 minutes
const BACKGROUND_TIMEOUT_MS = 60 * 1000;     // 60 seconds

let idleTimer = null;
let backgroundTimer = null;
let backgroundedAt = null;

function lockSession(reason) {
  if (state.passphrase === null) return; // already locked
  state.passphrase = null;
  state.selectedPadId = null;
  console.log('session locked:', reason);
  navigate('unlock');
}

function resetIdleTimer() {
  if (idleTimer) clearTimeout(idleTimer);
  if (state.passphrase === null) return; // not unlocked, nothing to time out
  idleTimer = setTimeout(() => lockSession('idle timeout'), IDLE_TIMEOUT_MS);
}

function setupAutoLock() {
  // Idle: any user input resets the timer.
  for (const evt of ['touchstart', 'keydown', 'click']) {
    document.addEventListener(evt, resetIdleTimer, { passive: true });
  }

  // Background: when the app goes to background, start a short countdown.
  // If the app comes back within the timeout, cancel. Otherwise lock.
  App.addListener('appStateChange', ({ isActive }) => {
    if (!isActive) {
      backgroundedAt = Date.now();
      if (backgroundTimer) clearTimeout(backgroundTimer);
      backgroundTimer = setTimeout(() => lockSession('background timeout'), BACKGROUND_TIMEOUT_MS);
    } else {
      // Foregrounded. If the timer already fired, we're already on unlock.
      if (backgroundTimer) {
        clearTimeout(backgroundTimer);
        backgroundTimer = null;
      }
      // Resync the idle timer on resume in case the user paused mid-session.
      resetIdleTimer();
    }
  });
}

async function boot() {
  setupAutoLock();
  const { value } = await Preferences.get({ key: PASSPHRASE_VERIFIER_KEY });
  state.screen = value ? 'unlock' : 'setup';
  render();
}

// ----------------------------------------------------------------------------
// Passphrase verifier
// ----------------------------------------------------------------------------
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
    if (decrypted.length !== KNOWN_MARKER.length) return false;
    for (let i = 0; i < KNOWN_MARKER.length; i++) {
      if (decrypted[i] !== KNOWN_MARKER[i]) return false;
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
      <p class="subtitle">This locks every pad on this device. There is no recovery if you forget it.</p>
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
      resetIdleTimer();
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
        resetIdleTimer();
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
        <button id="recv" class="full secondary">Receive pad (scan QR)</button>
        <button id="about" class="full secondary">About Veil</button>
      </div>
    </div>`;
  document.getElementById('new').onclick = () => navigate('create');
  document.getElementById('recv').onclick = () => navigate('receive');
  document.getElementById('about').onclick = () => navigate('about');
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
          <option value="262144" selected>256 KB — about 5,000 short messages</option>
          <option value="1048576">1 MB — about 20,000 short messages</option>
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
      wipeBytes(padSlice);
      wipeBytes(plaintext);

      document.getElementById('msg').value = '';  // clear plaintext from UI after success

      document.getElementById('enc-out').innerHTML = `
        <label>Ciphertext (send this via any channel)</label>
        <div class="cipher-output" id="ctout">${escapeHtml(b64)}</div>
        <button id="copyct" class="full secondary" style="margin-top:0.5rem">Copy to clipboard</button>
        <div class="hint">${plaintext.length} pad bytes consumed. New offset: ${newOffset}.</div>`;
      document.getElementById('copyct').onclick = async () => {
        try {
          await navigator.clipboard.writeText(b64);
          document.getElementById('copyct').textContent = 'Copied';
          setTimeout(() => {
            const btn = document.getElementById('copyct');
            if (btn) btn.textContent = 'Copy to clipboard';
          }, 1500);
        } catch (e) {
          err.textContent = `Clipboard copy failed: ${e.message}. Long-press the ciphertext to select manually.`;
        }
      };
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

    // Reject decrypt if the message references bytes already consumed on this device.
    // Means either pad desync or a replay. Either way: don't decrypt.
    if (offset < meta.offset) {
      err.textContent = `This message uses bytes 0-${offset + length - 1}, but this device has already consumed up to byte ${meta.offset}. Pad is desynchronized — possible replay or out-of-order message.`;
      return;
    }
    // Also reject if the offset jumps ahead — partner sent a message using
    // bytes we haven't seen yet, suggesting we missed an earlier message.
    if (offset > meta.offset) {
      err.textContent = `This message starts at byte ${offset}, but this device's next available byte is ${meta.offset}. A message between bytes ${meta.offset} and ${offset - 1} was missed. Cannot safely decrypt without it.`;
      return;
    }

    const ct = packet.slice(8);
    document.getElementById('dec').disabled = true;
    try {
      const { padBytes, parsed } = await unlockPad(id, state.passphrase);
      const padSlice = padBytes.slice(offset, offset + length);
      const plaintextBytes = xorBytes(ct, padSlice);
      const text = new TextDecoder().decode(plaintextBytes);

      // Advance the offset on this device too — the consumed bytes are now spent
      // for both parties. Without this step the two devices desynchronize and
      // the next message risks pad reuse.
      const newOffset = offset + length;
      await commitPadAdvance(id, padBytes, parsed, newOffset, state.passphrase);
      wipeBytes(padSlice);

      document.getElementById('dec-out').innerHTML = `
        <label>Plaintext</label>
        <div class="cipher-output">${escapeHtml(text)}</div>
        <div class="hint">${length} pad bytes consumed. New offset: ${newOffset}.</div>`;
      // Refresh meta so subsequent operations on this screen see the new offset
      meta = await readPadMetadata(id);
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
// Export screen
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

  root.innerHTML = `
    <div class="screen">
      <div class="back" id="back">← Cancel</div>
      <p class="eyebrow">Export</p>
      <h1 class="title">${escapeHtml(meta.name)}</h1>
      <p class="subtitle">Broadcast the pad to the recipient device as a sequence of QR codes.</p>
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

    root.innerHTML = `
      <div class="screen">
        <div class="back" id="back2">← Stop</div>
        <p class="eyebrow" id="eyebrow">Broadcasting · 0 / ${chunks.length}</p>
        <h1 class="title" style="font-size:1.5rem">${escapeHtml(meta.name)}</h1>
        <div style="display:flex;justify-content:center;margin:1.5rem 0">
          <canvas id="qr" width="600" height="600" style="background:#fff;border:none;border-radius:4px;width:90vw;max-width:600px;height:auto;aspect-ratio:1/1"></canvas>
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

    let i = 0;
    let intervalMs = 500;
    let paused = false;
    let stopped = false;

    document.getElementById('back2').onclick = () => {
      stopped = true;
      if (padBytes) wipeBytes(padBytes);
      navigate('pad', { padId: id });
    };

    pauseBtn.onclick = () => {
      paused = !paused;
      pauseBtn.textContent = paused ? 'Resume' : 'Pause';
    };
    slowBtn.onclick = () => {
      intervalMs = intervalMs === 500 ? 1000 : 500;
      slowBtn.textContent = intervalMs === 500 ? 'Half speed' : 'Full speed';
      rateHint.textContent = intervalMs === 500 ? '2 codes / second' : '1 code / second';
    };

    await renderChunkToCanvas(chunks[0], canvas, 600);
    eyebrow.textContent = `Broadcasting · 1 / ${chunks.length}`;
    prog.style.width = `${(1 / chunks.length) * 100}%`;
    i = 1;

    while (i < chunks.length && !stopped) {
      await sleep(intervalMs);
      if (stopped) break;
      if (paused) { i--; continue; }
      try {
        await renderChunkToCanvas(chunks[i], canvas, 600);
        eyebrow.textContent = `Broadcasting · ${i + 1} / ${chunks.length}`;
        prog.style.width = `${((i + 1) / chunks.length) * 100}%`;
      } catch (e) {
        eyebrow.textContent = `Render failed at chunk ${i}: ${e.message}`;
        break;
      }
      i++;
    }

    if (!stopped && i >= chunks.length) {
      i = 0;
      while (!stopped) {
        await sleep(intervalMs);
        if (stopped) break;
        if (paused) continue;
        await renderChunkToCanvas(chunks[i], canvas, 600);
        eyebrow.textContent = `Looping · ${i + 1} / ${chunks.length}`;
        i = (i + 1) % chunks.length;
      }
    }

    if (padBytes) wipeBytes(padBytes);
  };
}

// ----------------------------------------------------------------------------
// Receive screen
// ----------------------------------------------------------------------------
async function renderReceive() {
  root.innerHTML = `
    <div class="screen">
      <div class="back" id="back">← Library</div>
      <p class="eyebrow">Receive pad</p>
      <h1 class="title" style="font-size:2rem">Scan</h1>
      <p class="subtitle">Point the camera at the broadcasting device's QR sequence. Hold steady.</p>
      <div style="position:relative;background:var(--bg-2);border:1px solid var(--border);border-radius:4px;overflow:hidden;aspect-ratio:1/1;margin-bottom:1rem">
        <video id="video" style="width:100%;height:100%;object-fit:cover" autoplay muted playsinline></video>
        <div id="flash" style="position:absolute;inset:0;border:3px solid transparent;pointer-events:none;transition:border-color 100ms ease;border-radius:4px"></div>
      </div>
      <p class="eyebrow" id="status">Initializing camera…</p>
      <div class="bar"><div id="prog" style="width:0%"></div></div>
      <p class="hint" id="missing" style="margin-top:0.5rem"></p>
      <div id="err" class="error" style="margin-top:1rem"></div>
      <div style="margin-top:1rem;background:#000;border:1px solid var(--border);border-radius:4px;padding:0.5rem;font-family:var(--mono);font-size:0.6rem;color:#7a9a5e;max-height:14rem;overflow-y:auto;line-height:1.4" id="debug">debug log:</div>
      <div id="finalize" style="margin-top:1.5rem;display:none">
        <div class="ok" id="okmsg"></div>
        <div class="field" style="margin-top:1rem">
          <label>Name this pad</label>
          <input id="name" placeholder="Sender's name" />
        </div>
        <button id="save" class="full">Save pad</button>
      </div>
    </div>`;

  const video = document.getElementById('video');
  const flash = document.getElementById('flash');
  const statusEl = document.getElementById('status');
  const prog = document.getElementById('prog');
  const err = document.getElementById('err');
  const finalizeBox = document.getElementById('finalize');
  const okmsg = document.getElementById('okmsg');
  const debugEl = document.getElementById('debug');

  let scannerHandle = null;
  let session = new ReceptionSession();
  let stopped = false;
  let assembled = null;
  let decodeAttempts = 0;
  let decodeSuccesses = 0;
  let lastError = '';

  function dlog(msg) {
    const ts = new Date().toISOString().slice(11, 19);
    debugEl.textContent += `\n[${ts}] ${msg}`;
    debugEl.scrollTop = debugEl.scrollHeight;
  }

  function teardown() {
    stopped = true;
    if (scannerHandle) {
      try { scannerHandle.stop(); } catch {}
      scannerHandle = null;
    }
  }

  document.getElementById('back').onclick = () => {
    teardown();
    navigate('library');
  };

  // Environment probe BEFORE starting the scanner.
  dlog(`mediaDevices: ${!!navigator.mediaDevices}`);
  dlog(`getUserMedia: ${!!navigator.mediaDevices?.getUserMedia}`);
  try {
    const devs = await navigator.mediaDevices.enumerateDevices();
    dlog(`devices: ${devs.length}`);
    for (const d of devs) {
      dlog(`  ${d.kind}: ${d.label || '(unlabeled)'}`);
    }
  } catch (e) {
    dlog(`enumerateDevices threw: ${e.message}`);
  }

  // Periodic heartbeat showing decode counters
  const heartbeat = setInterval(() => {
    if (stopped) { clearInterval(heartbeat); return; }
    statusEl.textContent = `decode attempts: ${decodeAttempts} · successes: ${decodeSuccesses}`;
    if (lastError) {
      statusEl.textContent += ` · last err: ${lastError.slice(0, 40)}`;
    }
  }, 500);

  try {
    dlog('starting scanner...');
    scannerHandle = await startScanning(video, async (rawBytes) => {
      decodeSuccesses++;
      if (stopped) return;
      dlog(`decoded ${rawBytes.length}B: ${Array.from(rawBytes.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(' ')}...`);
      let chunk;
      try {
        chunk = parseChunk(rawBytes);
      } catch (e) {
        dlog(`parse rejected: ${e.message}`);
        return;
      }
      try {
        const isNew = await session.ingest(chunk);
        if (isNew) {
          dlog(`chunk ${chunk.index + 1}/${chunk.totalChunks} accepted`);
          flash.style.borderColor = 'var(--ok)';
          setTimeout(() => { flash.style.borderColor = 'transparent'; }, 100);
        } else {
          dlog(`duplicate chunk ${chunk.index}`);
        }
        const p = session.progress();
        prog.style.width = `${(p.received / p.total) * 100}%`;
        const remaining = p.total - p.received;
        if (remaining > 0 && remaining <= 20) {
          // show specific missing indices when close to done
          const missing = [];
          for (let k = 0; k < session.totalChunks; k++) {
            if (!session.received.has(k)) missing.push(k + 1);
            if (missing.length >= 10) break;
          }
          document.getElementById('missing').textContent = `Waiting for: ${missing.join(', ')}${remaining > 10 ? ' …' : ''}`;
        } else if (remaining > 20) {
          document.getElementById('missing').textContent = `${remaining} chunks remaining`;
        } else {
          document.getElementById('missing').textContent = '';
        }
        if (p.ready) {
          teardown();
          dlog('all chunks received, assembling...');
          try {
            assembled = await session.assemble();
            dlog(`assembled ${assembled.length} bytes`);
            okmsg.textContent = `Reception complete. ${assembled.length.toLocaleString()} pad bytes verified.`;
            finalizeBox.style.display = 'block';
          } catch (e) {
            err.textContent = `Integrity check failed: ${e.message}`;
            dlog(`assemble error: ${e.message}`);
          }
        }
      } catch (e) {
        lastError = e.message;
        dlog(`ingest error: ${e.message}`);
      }
    }, (hadResult, errName) => {
      decodeAttempts++;
      if (errName && errName !== 'NotFoundException' && errName !== 'NotFoundException2') {
        lastError = errName;
      }
    });
    dlog('scanner started');
    // Log stream resolution AFTER scanner has started — getUserMedia has resolved by now
    const tracks = video.srcObject?.getVideoTracks?.() ?? [];
    for (const t of tracks) {
      const s = t.getSettings();
      dlog(`stream: ${s.width}x${s.height} ${s.frameRate || '?'}fps ${s.facingMode || ''}`);
    }
  } catch (e) {
    err.textContent = `Camera failed: ${e.message}`;
    dlog(`startScanning threw: ${e.message}`);
    return;
  }

  document.getElementById('save').onclick = async () => {
    err.textContent = '';
    const name = document.getElementById('name').value.trim();
    if (!name) { err.textContent = 'Name required.'; return; }
    if (!assembled) { err.textContent = 'No assembled pad to save.'; return; }
    document.getElementById('save').disabled = true;
    try {
      await importPad({
        id: session.padId,
        name,
        padBytes: assembled,
        passphrase: state.passphrase
      });
      assembled = null;
      navigate('library');
    } catch (e) {
      err.textContent = `Save failed: ${e.message}`;
      document.getElementById('save').disabled = false;
    }
  };
}

// ----------------------------------------------------------------------------
// About screen
// ----------------------------------------------------------------------------
async function renderAbout() {
  // Probe the runtime to display real values, not hardcoded ones.
  const probe = new Uint8Array(8);
  crypto.getRandomValues(probe);
  const probeHex = Array.from(probe).map(b => b.toString(16).padStart(2, '0')).join('');
  const ua = navigator.userAgent;
  const subtleAvailable = !!crypto.subtle;

  root.innerHTML = `
    <div class="screen">
      <div class="back" id="back">← Library</div>
      <p class="eyebrow">About</p>
      <h1 class="title">Veil</h1>
      <p class="subtitle">A one-time pad messenger. Information-theoretic perfect secrecy when used correctly. Read this before relying on it.</p>

      <h2 style="font-family:var(--serif);font-size:1.4rem;color:var(--copper);margin-top:2rem;margin-bottom:0.5rem">What this app is</h2>
      <p style="color:var(--fg-dim);line-height:1.6;margin-bottom:1rem">Veil implements the one-time pad — the only cipher with mathematical proof of unbreakability (Shannon, 1949). Each character of message material XORs with one byte of true random pad. Pad bytes are consumed on use and never reused. If the pad is truly random, never reused, and kept secret, the ciphertext reveals nothing about the plaintext to any adversary regardless of their computational power.</p>

      <h2 style="font-family:var(--serif);font-size:1.4rem;color:var(--copper);margin-top:1.5rem;margin-bottom:0.5rem">What this app is not</h2>
      <p style="color:var(--fg-dim);line-height:1.6;margin-bottom:1rem">It is not a replacement for Signal or any modern end-to-end encrypted messenger. The pad must be exchanged in person via QR. The pad runs out — a 1 MB pad supports about 20,000 short messages. If you lose the pad you lose all future communication with that contact. There is no recovery from a forgotten passphrase. There is no cloud sync. The threat model is small, deliberate, and offline.</p>

      <h2 style="font-family:var(--serif);font-size:1.4rem;color:var(--copper);margin-top:1.5rem;margin-bottom:0.5rem">Entropy source</h2>
      <div style="background:var(--bg-2);border:1px solid var(--border);padding:1rem;border-radius:4px;font-family:var(--mono);font-size:0.75rem;color:var(--fg-dim);line-height:1.7;margin-bottom:1rem">
        Source: <span style="color:var(--ok)">crypto.getRandomValues</span> (W3C WebCrypto API)<br>
        Backed by: <span style="color:var(--ok)">java.security.SecureRandom</span> on Android<br>
        Live probe: <span style="color:var(--copper)">${probeHex}</span><br>
        AES-GCM available: <span style="color:${subtleAvailable ? 'var(--ok)' : 'var(--danger)'}">${subtleAvailable ? 'yes' : 'no'}</span><br>
        Argon2id KDF: <span style="color:var(--ok)">via hash-wasm</span> (t=3, m=64MB, p=1)
      </div>

      <h2 style="font-family:var(--serif);font-size:1.4rem;color:var(--copper);margin-top:1.5rem;margin-bottom:0.5rem">Pad discipline</h2>
      <p style="color:var(--fg-dim);line-height:1.6;margin-bottom:1rem">Every byte consumed in encryption or decryption is overwritten with zeros in the encrypted-at-rest pad file before the file is rewritten. Used bytes are gone — even if your device is later seized and the passphrase is brute-forced, the bytes already used cannot be recovered. The remaining unconsumed pad still protects future messages between you and your partner.</p>

      <h2 style="font-family:var(--serif);font-size:1.4rem;color:var(--copper);margin-top:1.5rem;margin-bottom:0.5rem">Honest caveats</h2>
      <p style="color:var(--fg-dim);line-height:1.6;margin-bottom:0.5rem"><strong style="color:var(--fg)">Memory wipe is best-effort.</strong> JavaScript provides no guarantee that overwriting a byte array zeros the underlying memory. The V8 garbage collector may have copied the buffer during execution. We zero what we can see; we cannot zero what we cannot see.</p>
      <p style="color:var(--fg-dim);line-height:1.6;margin-bottom:0.5rem"><strong style="color:var(--fg)">QR transfer is in-person only.</strong> A photo or screen recording of the QR sequence by an adversary captures the pad. Treat the handshake like a key exchange — observed only by you and your partner.</p>
      <p style="color:var(--fg-dim);line-height:1.6;margin-bottom:0.5rem"><strong style="color:var(--fg)">No network protection.</strong> Ciphertext sent over WhatsApp, SMS, email, or any channel is fine — the OTP guarantees confidentiality. But metadata (when, who, how often) leaks through whatever channel you use. Veil does not hide the fact that you communicate.</p>
      <p style="color:var(--fg-dim);line-height:1.6;margin-bottom:1rem"><strong style="color:var(--fg)">No backup.</strong> Lose the device, lose the pads. By design.</p>

      <h2 style="font-family:var(--serif);font-size:1.4rem;color:var(--copper);margin-top:1.5rem;margin-bottom:0.5rem">Build</h2>
      <div style="background:var(--bg-2);border:1px solid var(--border);padding:1rem;border-radius:4px;font-family:var(--mono);font-size:0.7rem;color:var(--muted);line-height:1.6;word-break:break-all">
        ${escapeHtml(ua)}
      </div>
      <p style="color:var(--muted);font-family:var(--mono);font-size:0.7rem;margin-top:1rem;line-height:1.6">Veil v0.1 · built by Krishna J · Knowledge Institute of Technology, Salem · paired with CryptoForge as the unconditional / conditional cryptography duo.</p>
    </div>`;

  document.getElementById('back').onclick = () => navigate('library');
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
function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

boot().catch(e => {
  root.innerHTML = `<div class="screen"><div class="error">Boot failed: ${escapeHtml(e.message)}</div></div>`;
});