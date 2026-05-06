# How to use Veil

A practical guide for two people who want to send each other private messages.

## What you need

- Two Android phones (running Android 10 or later)
- The Veil APK installed on both phones
- About 5 minutes face-to-face for the initial pad handshake

That's it. After the handshake the two phones never need to be in the same room again.

## First-time setup

### On both phones

1. Open Veil
2. Set a passphrase — at least 12 characters. This locks the pads on this device. **There is no recovery if you forget it.** Pick something memorable but long. The passphrase on each phone can be different — you do not need to coordinate.
3. After the passphrase, you land on the empty Pad Library

### Generating and exchanging the first pad

Decide which phone will be the **broadcaster** (any one of the two — it doesn't matter). The other becomes the **receiver**.

**On the broadcaster phone:**

1. Tap **+ New pad**
2. Type the receiver's name (e.g. "Alice")
3. Choose a pad size:
   - **256 KB** — about 5,000 short messages
   - **1 MB** — about 20,000 short messages
   - **4 MB** — about 80,000 short messages
4. Tap **Generate pad**. The phone produces ~256 KB to 4 MB of true random bytes from the OS CSPRNG and encrypts them at rest with your passphrase.
5. The new pad appears in the library. Tap it.
6. Tap **Export to other device (QR)**
7. Tap **Start broadcasting**

The screen now shows a QR code that changes twice per second. The chunk counter at the top tells you how many of the total chunks have been broadcast. The codes loop forever until the receiver has them all.

**On the receiver phone:**

1. Tap **Receive pad (scan QR)**. Grant camera permission on first use.
2. Hold the receiver phone about 15 cm above the broadcaster phone, screen facing screen
3. Both phones at full brightness, no reflections, steady hands
4. Watch the chunk counter climb. Most chunks come through on the first pass, a handful need the broadcast to loop back around.
5. When all chunks are received, the screen shows "Reception complete. X pad bytes verified."
6. Type the broadcaster's name (e.g. "Bob") and tap **Save pad**

Both phones now hold the same pad. They are encrypted at rest under each phone's own passphrase. The handshake is permanent — these two pads are linked forever (or until exhausted, whichever comes first).

### How long does this take?

| Pad size | Chunks | Minimum broadcast time | Realistic completion |
|----------|--------|------------------------|----------------------|
| 256 KB   | 328    | 2.5 minutes            | 3–5 minutes          |
| 1 MB     | 1,311  | 11 minutes             | 12–15 minutes        |
| 4 MB     | 5,243  | 44 minutes             | 50+ minutes          |

For a first pad, use 256 KB. You can always handshake a fresh pad later when you need more capacity.

## Sending messages

Once both phones have the same pad, you can exchange messages from anywhere. The two phones never need to be near each other again.

**Sender:**

1. Open Veil, unlock with passphrase
2. Tap the contact's pad in the library
3. Type a message in the **Compose Message** box
4. Tap **Encrypt**. The pad bytes used to encrypt are zeroed in storage immediately.
5. The ciphertext appears as a base64 string. Tap **Copy to clipboard**.
6. Send the ciphertext through any channel — WhatsApp, SMS, email, paper, anything. The channel doesn't need to be secure. Only the holder of the matching pad can decrypt it.

**Receiver:**

1. Open Veil, unlock with passphrase
2. Tap the same contact's pad
3. Paste the ciphertext into the **Decrypt Ciphertext** box
4. Tap **Decrypt**. The plaintext appears in the Plaintext box, and the same pad bytes are zeroed on this device too.

The two devices stay in offset-sync as long as messages are decrypted in the order they were sent.

### What if I miss a message or receive one out of order?

Veil rejects desynchronized messages instead of silently producing garbage. If you try to decrypt a message that uses pad bytes already consumed (replay), or one that uses bytes you haven't seen yet (a previous message was missed), the app shows an error explaining what happened. Resolve by checking with the sender — usually a missed message just needs to be re-sent in order.

## Daily use

- Each character consumes 1 byte of pad. Multi-byte characters (emoji, non-Latin scripts) consume more — typically 2–4 bytes per character.
- The pad library shows bytes remaining for each contact. Once a pad is exhausted, you need a fresh in-person handshake to keep communicating with that contact.
- The app auto-locks after 60 seconds in background or 5 minutes of inactivity. You'll re-enter the passphrase to continue.

## Things that should make you nervous

- **A photo or screen recording of the QR sequence captures the pad.** Treat the handshake like a key exchange — observed only by you and your partner.
- **Losing the device with the pad means losing all communication with that contact.** No backup. By design.
- **Forgetting the passphrase means the pads are unrecoverable.** No reset link.
- **Veil hides what you say but not the fact that you communicate.** Whatever channel you use to send the ciphertext leaks who-talks-to-whom and when. If that matters, use a channel that doesn't (Tor, Signal, paper).
- **The "secure wipe" of consumed pad bytes is best-effort.** JavaScript can't guarantee memory zeroing. The on-disk wipe is reliable; the in-RAM wipe is approximate.

## When NOT to use Veil

- Day-to-day messaging where Signal is fine. Signal is more convenient, hides metadata, and offers practical security for normal threat models.
- Anything where you can't meet the other person to handshake. Veil cannot bootstrap from a remote-only relationship.
- Long messages or file transfer. Veil is built for short text. A pad sized for 1 MB of messages is also a 1 MB transfer overhead per handshake.

## When Veil is the right tool

- Two people who need provable secrecy for short messages
- A face-to-face handshake is feasible at least once
- The threat model includes adversaries who might break standard ciphers in 5–30 years (state actors, future quantum computers, etc.)
- The participants are willing to trade convenience for cryptographic certainty

## Support

This is a research project, not a commercial product. Issues at https://github.com/23f2001849/veil/issues. No SLA, no guarantees.
