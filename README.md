# Veil

A mobile-first one-time pad messenger. Two phones exchange a true-random pad in person via QR codes, then send each other short messages with information-theoretic perfect secrecy. The pad is consumed on use, never reused, never leaves the device unencrypted.

## What this is

Veil implements the only cipher with a mathematical proof of unbreakability — Shannon, 1949. Each character of message material XORs with one byte of true random pad. If the pad is genuinely random, never reused, and kept secret, the ciphertext reveals nothing about the plaintext to any adversary regardless of computational power.

The hard part of the one-time pad has always been key distribution. Veil solves it the only way the math allows: in person. Two phones face each other, one broadcasts the pad as an animated sequence of QR codes, the other scans them with the camera. Once the handshake completes both devices hold the same pad bytes, encrypted at rest under each user's own passphrase. Messages can then be exchanged through any channel — WhatsApp, SMS, paper, smoke signal — and only the holder of the matching pad can read them.

## Features

- **Pad generation** from the OS CSPRNG. 256 KB / 1 MB / 4 MB.
- **In-person QR handshake**. Sequenced QR codes with chained per-chunk hashes for ordering verification. Auto-loops until the receiver confirms all chunks.
- **AES-256-GCM at rest**. Pads are never stored in plaintext on disk.
- **Argon2id KDF** for the device passphrase. 64 MB memory cost, 3 iterations.
- **Pad consumption discipline**. Used bytes are zeroed in the encrypted file before being rewritten. Once spent, the bytes are gone — even if the device is later compromised.
- **Desync detection** on decrypt. Replays and skipped messages are rejected, not silently decrypted to garbage.
- **Auto-lock** after 60 seconds in background or 5 minutes idle.
- **Honest about limits**. The About screen surfaces the entropy source, the JavaScript memory-wipe caveat, and the fact that Veil hides message contents but not metadata.

## Stack

- Capacitor 6 (web → native APK wrapper)
- Vite 8 (build)
- Plain JavaScript, no framework
- WebCrypto API for AES-GCM, SHA-256, CSPRNG
- hash-wasm for Argon2id
- qrcode for QR generation
- jsQR for scanning
- Capacitor Filesystem for encrypted pad storage

No backend. No network calls. No telemetry. The app runs entirely on-device.

## Build

Requirements:

- Node 20+
- JDK 17
- Android SDK with platform-34

```bash
npm install
npm run build
npx cap sync android
cd android
./gradlew assembleDebug    # development build
./gradlew assembleRelease  # signed release (requires keystore.properties)
```

Release builds need a keystore. The `keystore.properties` file lives at `android/keystore.properties` and is gitignored. For local debug testing, the debug build is sufficient.

## Install

Sideload only. There is no Play Store listing.

1. Download `app-release.apk` from the [Releases page](https://github.com/23f2001849/veil/releases)
2. On Android: enable "Install unknown apps" for your browser or file manager
3. Install the APK
4. Open Veil and follow the in-app guide

User-facing setup is documented in [HOW_TO_USE.md](HOW_TO_USE.md).

## Cryptographic notes

**One-time pad correctness.** XOR is the encryption. The pad must be at least as long as the message, generated from a true random source, used exactly once, and shared in advance only between the two parties. Veil enforces all four: pad bytes come from `crypto.getRandomValues` (which is backed by `java.security.SecureRandom` on Android), each pad is generated fresh, the offset is monotonic and consumed bytes are zeroed in storage, and the only way to share a pad is the QR handshake.

**At-rest encryption.** The pad file on disk is AES-256-GCM ciphertext. The key is derived from the user's passphrase via Argon2id with a per-pad random salt. The plaintext pad never touches non-volatile storage.

**Memory wipe is best-effort.** JavaScript provides no guarantee that overwriting a `Uint8Array` zeros the underlying memory — V8 may have copied the buffer during execution. Veil zeros what it can see. Surfaced honestly in the About screen.

**Threat model.** Veil protects message contents from any third party who lacks the pad, regardless of their computational resources. Veil does NOT hide metadata (who you talk to, when, how often) — that depends on whatever channel you send the ciphertext through. Veil does NOT survive a compromised device that has the pad and passphrase. Veil is not a substitute for Signal in any normal threat model; it's the cipher to use when you need provable secrecy for short messages between two people who can meet in person to handshake.

## Companion project: CryptoForge

Veil pairs with [CryptoForge](https://github.com/23f2001849/cryptoforge-web), a research project on adversarial co-evolution for cryptographic hash function design. The two projects are intentional opposites:

- **CryptoForge**: computational security, designs hashes that resist neural cryptanalysis under conditional security assumptions
- **Veil**: information-theoretic security, the one cipher whose security holds even against adversaries with unlimited compute

Together they cover the full spectrum from "secure if our assumptions hold" to "secure if math holds."

## Acknowledgements

Built at the Department of Artificial Intelligence and Data Science, Knowledge Institute of Technology, Salem. Mentored by Dr. Esther Rani P J.

## License

MIT — see [LICENSE](LICENSE).
