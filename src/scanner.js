// QR scanner + reception state machine for incoming pad chunks.
// Uses jsQR with a manual frame loop. jsQR handles inverted QRs and has
// better real-world phone-to-phone scan reliability than ZXing's JS port.

import jsQR from 'jsqr';
import { parseChunk, QR_FORMAT } from './qr.js';
import { sha256, bytesToHex } from './crypto.js';

export class ReceptionSession {
  constructor() {
    this.padId = null;
    this.totalChunks = null;
    this.padBytes = null;
    this.payloadLens = null;
    this.prevHashes = null;
    this.received = new Set();
    this.lastChunkIndex = -1;
  }

  async ingest(chunk) {
    if (this.padId === null) {
      this.padId = chunk.padId;
      this.totalChunks = chunk.totalChunks;
      this.padBytes = new Uint8Array(this.totalChunks * QR_FORMAT.PAYLOAD_MAX);
      this.payloadLens = new Array(this.totalChunks).fill(0);
      this.prevHashes = new Array(this.totalChunks).fill(null);
    }

    if (chunk.padId !== this.padId) {
      throw new Error(`pad id mismatch: session is ${this.padId}, chunk is ${chunk.padId}`);
    }
    if (chunk.totalChunks !== this.totalChunks) {
      throw new Error(`total chunks mismatch: session is ${this.totalChunks}, chunk says ${chunk.totalChunks}`);
    }
    if (chunk.index >= this.totalChunks) {
      throw new Error(`chunk index ${chunk.index} >= total ${this.totalChunks}`);
    }

    if (this.received.has(chunk.index)) {
      return false;
    }

    const offset = chunk.index * QR_FORMAT.PAYLOAD_MAX;
    this.padBytes.set(chunk.payload, offset);
    this.payloadLens[chunk.index] = chunk.payload.length;
    this.prevHashes[chunk.index] = chunk.prevHash;

    this.received.add(chunk.index);
    this.lastChunkIndex = chunk.index;
    return true;
  }

  progress() {
    return {
      received: this.received.size,
      total: this.totalChunks ?? 0,
      ready: this.totalChunks !== null && this.received.size === this.totalChunks
    };
  }

  async assemble() {
    if (!this.progress().ready) throw new Error('not all chunks received');

    for (let i = 1; i < this.totalChunks; i++) {
      const prevPayload = this._payloadAt(i - 1);
      const expected = (await sha256(prevPayload)).subarray(0, 16);
      const claimed = this.prevHashes[i];
      for (let j = 0; j < 16; j++) {
        if (expected[j] !== claimed[j]) {
          throw new Error(`integrity failure at chunk ${i}: prev_hash mismatch (chunk ${i - 1} corrupted or out of order)`);
        }
      }
    }

    const firstPrev = this.prevHashes[0];
    for (let j = 0; j < 16; j++) {
      if (firstPrev[j] !== 0) {
        throw new Error(`integrity failure at chunk 0: prev_hash should be zero, got nonzero`);
      }
    }

    let totalSize = 0;
    for (const len of this.payloadLens) totalSize += len;
    const out = new Uint8Array(totalSize);
    let pos = 0;
    for (let i = 0; i < this.totalChunks; i++) {
      const payload = this._payloadAt(i);
      out.set(payload, pos);
      pos += payload.length;
    }
    return out;
  }

  _payloadAt(index) {
    const start = index * QR_FORMAT.PAYLOAD_MAX;
    const len = this.payloadLens[index];
    return this.padBytes.subarray(start, start + len);
  }
}

// Live camera scanner using jsQR + manual frame loop.
//
// Why manual: jsQR is a pure decoder, no camera plumbing. We grab frames from
// the video element to a hidden canvas, get its ImageData, and pass that to
// jsQR. This gives us full control over framerate, resolution, and inversion.
//
// onResult(uint8Array) is called once per successful decode.
// onAttempt(hadResult, errName) is called once per frame attempt.
export async function startScanning(videoElement, onResult, onAttempt) {
  // Pick the rear camera.
  let deviceId = null;
  try {
    const devices = await navigator.mediaDevices.enumerateDevices();
    const videoInputs = devices.filter(d => d.kind === 'videoinput');
    const rear = videoInputs.find(d => /back|rear|environment/i.test(d.label));
    deviceId = rear ? rear.deviceId : (videoInputs[videoInputs.length - 1]?.deviceId ?? null);
  } catch {}

  // High-res constraints. Camera will fall back to closest supported mode.
  // continuous focus is critical for phone-to-phone scanning at close range.
  const constraints = {
    video: {
      facingMode: deviceId ? undefined : { ideal: 'environment' },
      deviceId: deviceId ? { exact: deviceId } : undefined,
      width:  { ideal: 1920 },
      height: { ideal: 1080 },
      // Hint the camera into continuous-autofocus mode. Browsers ignore this
      // if unsupported. Critical: without continuous AF, the camera locks at
      // infinity on app launch and never focuses on a screen 15cm away.
      advanced: [
        { focusMode: 'continuous' },
        { focusMode: 'auto' }
      ]
    }
  };

  const stream = await navigator.mediaDevices.getUserMedia(constraints);
  videoElement.srcObject = stream;
  videoElement.setAttribute('playsinline', 'true');
  videoElement.setAttribute('muted', 'true');
  await videoElement.play().catch(() => {});

  // Wait for video to actually have dimensions before starting the decode loop
  await new Promise(resolve => {
    if (videoElement.readyState >= 2 && videoElement.videoWidth > 0) {
      resolve();
    } else {
      const onReady = () => {
        if (videoElement.videoWidth > 0) {
          videoElement.removeEventListener('loadedmetadata', onReady);
          resolve();
        }
      };
      videoElement.addEventListener('loadedmetadata', onReady);
      // Fail-safe timeout — if metadata never fires, proceed anyway after 2s
      setTimeout(resolve, 2000);
    }
  });

  // Off-screen canvas for frame capture
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d', { willReadFrequently: true });

  let stopped = false;
  let rafId = null;

function loop() {
    if (stopped) return;
    if (videoElement.readyState >= 2 && videoElement.videoWidth > 0) {
      const w = videoElement.videoWidth;
      const h = videoElement.videoHeight;

      // Crop to center square — the QR will be centered in the viewport.
      // jsQR gets a much smaller, more focused image, runs faster, and
      // has fewer false finder-pattern candidates from non-QR content.
      const side = Math.min(w, h);
      const sx = (w - side) / 2;
      const sy = (h - side) / 2;
      // Downsample to 720x720 — sufficient for a 57x57 module QR
      const target = Math.min(side, 720);
      if (canvas.width !== target) {
        canvas.width = target;
        canvas.height = target;
      }
      ctx.drawImage(videoElement, sx, sy, side, side, 0, 0, target, target);
      const imageData = ctx.getImageData(0, 0, target, target);

      let result = null;
      let errName = null;
      try {
        result = jsQR(imageData.data, target, target, {
          inversionAttempts: 'dontInvert'  // we now render standard polarity
        });
      } catch (e) {
        errName = e.name || 'DecodeError';
      }

      if (onAttempt) onAttempt(!!result, errName);

      if (result && result.binaryData && result.binaryData.length > 0) {
        onResult(new Uint8Array(result.binaryData));
      }
    } else {
      if (onAttempt) onAttempt(false, 'video-not-ready');
    }
    rafId = requestAnimationFrame(loop);
  }

  rafId = requestAnimationFrame(loop);

  return {
    stop: () => {
      stopped = true;
      if (rafId !== null) cancelAnimationFrame(rafId);
      try {
        for (const track of stream.getTracks()) track.stop();
      } catch {}
    }
  };
}

export { parseChunk };