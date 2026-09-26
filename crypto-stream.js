// ════════════════════════════════════════════════════════════════════
// crypto-stream.js
//
// Chunked, streaming AEAD (AES-256-GCM) encryption for file uploads/
// downloads, plus a small resumable-upload client for Google Drive.
//
// Nothing here touches the DOM. app.js calls into this module for the
// "file" clip type; text clips keep using the plain whole-buffer
// AES-GCM helpers already in app.js (text is always tiny).
//
// ── Why chunked? ────────────────────────────────────────────────────
// A single AES-GCM call has to hold its whole input (and, on decrypt,
// verify its whole input) before producing any output. For a large
// file that means the entire file in memory twice over (plaintext +
// ciphertext) on both ends. Splitting the file into independent,
// separately-authenticated chunks means at any moment we only ever
// need ~one chunk's worth of memory, and a corrupted/tampered chunk
// is caught (and reported) as soon as it's read, not after the whole
// file has been downloaded.
// ════════════════════════════════════════════════════════════════════

// ── Tunables (safe to change; new values only affect new uploads —
//    every file's own chunk size travels with it in its header, so
//    old files keep decrypting correctly forever) ────────────────────

const CFEC_CHUNK_SIZE      = 8 * 1024 * 1024; // 8 MiB plaintext per AEAD chunk
const CFEC_UPLOAD_WINDOW   = 8 * 1024 * 1024; // bytes per Drive resumable PUT — MUST be a multiple of 256 KiB (262144)
const CFEC_MAX_CHUNK_RETRY = 5;               // retries for a single upload window before giving up on the session
const CFEC_MAX_FULL_RETRY  = 2;               // full restarts (fresh session, re-read file from byte 0) before surfacing an error
const CFEC_MAX_DL_RETRY    = 3;               // full download restarts before surfacing an error

// ── Container format ──────────────────────────────────────────────
//
// This is intentionally a flat, versioned binary format so it can
// change later without breaking files already sitting in Drive: a
// decoder always checks the magic + version first and every field
// needed to decrypt a chunk (chunk size, original size, nonce prefix,
// KDF salt/iterations) travels in the header rather than being
// assumed from current code.
//
//   Offset  Len  Field
//   ------  ---  -----------------------------------------------------
//        0    4  magic              "CFEC"
//        4    1  version            currently 1
//        5    1  flags              bit0 = 1 -> password/PBKDF2 mode,
//                                            0 -> raw random key mode
//        6    4  chunkSize          uint32 LE, plaintext bytes/chunk
//       10    8  originalSize       uint64 LE, total plaintext bytes
//       18    4  noncePrefix        random per-file, see "Nonces" below
//       22    4  kdfIterations      uint32 LE (0 if not password mode)
//       26    1  saltLen            16 if password mode, else 0
//       27  ...  salt               saltLen bytes
//
// Followed by one record per chunk, back to back, with NO trailing
// data after the last one:
//
//   Offset  Len  Field
//   ------  ---  -----------------------------------------------------
//        0    4  ciphertextLen      uint32 LE (includes the 16-byte tag)
//        4  ... ciphertext+tag      as produced by AES-GCM (WebCrypto
//                                   appends the tag to the ciphertext)
//
// Nonces: rather than storing a 12-byte nonce per chunk (wasted space,
// and one more thing that could be tampered with independently of the
// data it's paired with), the nonce is derived deterministically as
//     nonce = noncePrefix (4 random bytes, from the header)
//          || chunkIndex   (8 bytes, big-endian, 0-based)
// This guarantees every chunk in a file gets a unique nonce (the
// counter never repeats) without needing 2^96 worth of luck, which
// matters once a large file produces thousands of chunks under the
// same key.
//
// Authentication: each chunk's AES-GCM call also binds 10 bytes of
// "additional authenticated data" — format version, the chunk's own
// index, and whether it's the final chunk — into the tag. Combined
// with the flush()-time check that the total plaintext length equals
// the header's originalSize, this catches truncation, reordering, and
// splicing of chunks between files, not just bit-flips within one.
// ════════════════════════════════════════════════════════════════════

const CFEC_MAGIC             = new Uint8Array([0x43, 0x46, 0x45, 0x43]); // "CFEC"
const CFEC_VERSION           = 1;
const CFEC_HEADER_FIXED_LEN  = 27; // everything up to (not including) the salt
const CFEC_CHUNK_OVERHEAD    = 4 + 16; // 4-byte length prefix + 16-byte GCM tag

function cfecDelay(ms) { return new Promise(r => setTimeout(r, ms)); }

function cfecConcat(a, b) {
  if (a.length === 0) return b;
  if (b.length === 0) return a;
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

// ── Header encode/decode ──────────────────────────────────────────

function cfecEncodeHeader({ chunkSize, originalSize, noncePrefix, passwordMode, iterations, salt }) {
  const saltLen = passwordMode ? salt.length : 0;
  const buf = new Uint8Array(CFEC_HEADER_FIXED_LEN + saltLen);
  const dv  = new DataView(buf.buffer);
  buf.set(CFEC_MAGIC, 0);
  buf[4] = CFEC_VERSION;
  buf[5] = passwordMode ? 1 : 0;
  dv.setUint32(6, chunkSize, true);
  dv.setBigUint64(10, BigInt(originalSize), true);
  buf.set(noncePrefix, 18);
  dv.setUint32(22, iterations || 0, true);
  buf[26] = saltLen;
  if (saltLen) buf.set(salt, 27);
  return buf;
}

// Throws on anything that doesn't look like a valid header for a
// version we understand — callers should treat that as "cannot
// decrypt this file", not silently fall back to guessing.
function cfecDecodeHeader(buf) {
  for (let i = 0; i < 4; i++) {
    if (buf[i] !== CFEC_MAGIC[i]) throw new Error("Not a recognised encrypted-file container (bad magic bytes)");
  }
  const version = buf[4];
  if (version !== CFEC_VERSION) throw new Error("Unsupported encrypted-file format version: " + version);
  const dv           = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const passwordMode = !!buf[5];
  const chunkSize    = dv.getUint32(6, true);
  const originalSize = Number(dv.getBigUint64(10, true));
  const noncePrefix  = buf.slice(18, 22);
  const iterations   = dv.getUint32(22, true);
  const saltLen      = buf[26];
  const salt         = saltLen ? buf.slice(27, 27 + saltLen) : null;
  return { version, passwordMode, chunkSize, originalSize, noncePrefix, iterations, saltLen, salt, headerLen: 27 + saltLen };
}

function cfecComputeCiphertextSize(originalSize, chunkSize, saltLen = 0) {
  const numChunks = originalSize === 0 ? 1 : Math.ceil(originalSize / chunkSize);
  return CFEC_HEADER_FIXED_LEN + saltLen + numChunks * CFEC_CHUNK_OVERHEAD + originalSize;
}

// ── Nonce / AAD derivation ────────────────────────────────────────

function cfecBuildNonce(noncePrefix4, chunkIndex) {
  const nonce = new Uint8Array(12);
  nonce.set(noncePrefix4, 0);
  const dv = new DataView(nonce.buffer);
  dv.setUint32(4, 0, false);          // high 32 bits of the counter (always 0 this side of exabyte files)
  dv.setUint32(8, chunkIndex, false); // low 32 bits
  return nonce;
}

function cfecBuildAAD(version, chunkIndex, isLast) {
  const aad = new Uint8Array(10);
  aad[0] = version;
  const dv = new DataView(aad.buffer);
  dv.setUint32(1, 0, false);
  dv.setUint32(5, chunkIndex, false);
  aad[9] = isLast ? 1 : 0;
  return aad;
}

// ── Upload side: File -> fixed-size plaintext chunks -> encrypted stream ──

// Reads a File in fixed-size windows without ever holding more than
// one window in memory. Zero-byte files still emit exactly one
// (empty) chunk, so the container format always has >= 1 record.
function cfecFileToChunkStream(file, chunkSize) {
  const total = file.size;
  let offset = 0;
  let emittedEmpty = false;
  return new ReadableStream({
    async pull(controller) {
      if (total === 0) {
        if (!emittedEmpty) { emittedEmpty = true; controller.enqueue(new Uint8Array(0)); }
        else controller.close();
        return;
      }
      if (offset >= total) { controller.close(); return; }
      const end = Math.min(offset + chunkSize, total);
      const buf = await file.slice(offset, end).arrayBuffer();
      offset = end;
      controller.enqueue(new Uint8Array(buf));
    },
  });
}

function cfecCreateEncryptTransform({ key, noncePrefix, totalPlainSize }) {
  let index = 0;
  let seenBytes = 0;
  return new TransformStream({
    async transform(chunk, controller) {
      seenBytes += chunk.byteLength;
      const isLast = seenBytes >= totalPlainSize;
      const nonce  = cfecBuildNonce(noncePrefix, index);
      const aad    = cfecBuildAAD(CFEC_VERSION, index, isLast);
      const ct     = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, key, chunk);
      const ctBytes = new Uint8Array(ct);
      const record  = new Uint8Array(4 + ctBytes.length);
      new DataView(record.buffer).setUint32(0, ctBytes.length, true);
      record.set(ctBytes, 4);
      controller.enqueue(record);
      index++;
    },
  });
}

// Produces the full ciphertext byte stream (header followed by every
// chunk record) for a file. `header` must already contain chunkSize,
// originalSize, noncePrefix, passwordMode, iterations, salt.
function cfecBuildCiphertextStream({ file, key, header }) {
  const headerBytes = cfecEncodeHeader(header);
  const plainSource  = cfecFileToChunkStream(file, header.chunkSize);
  const encrypted    = plainSource.pipeThrough(
    cfecCreateEncryptTransform({ key, noncePrefix: header.noncePrefix, totalPlainSize: header.originalSize })
  );
  const reader = encrypted.getReader();
  let headerSent = false;

  return new ReadableStream({
    async pull(controller) {
      if (!headerSent) { headerSent = true; controller.enqueue(headerBytes); return; }
      const { value, done } = await reader.read();
      if (done) { controller.close(); return; }
      controller.enqueue(value);
    },
    cancel(reason) { return reader.cancel(reason); },
  });
}

// Re-groups an arbitrary-chunked byte stream into fixed-size windows
// (the final window may be shorter), stopping once `totalSize` bytes
// have been produced. Used so upload windows can satisfy Drive's
// "multiple of 256 KiB" rule regardless of where AEAD chunk
// boundaries happen to fall.
async function* cfecFixedWindows(stream, windowSize, totalSize) {
  const reader = stream.getReader();
  let buffered = new Uint8Array(0);
  let sent = 0;
  try {
    while (sent < totalSize) {
      while (buffered.length < windowSize && sent + buffered.length < totalSize) {
        const { value, done } = await reader.read();
        if (done) break;
        buffered = cfecConcat(buffered, value);
      }
      if (buffered.length === 0) break;
      const take = Math.min(windowSize, buffered.length);
      const windowBytes = buffered.slice(0, take);
      buffered = buffered.slice(take);
      sent += windowBytes.length;
      yield { bytes: windowBytes, isFinal: sent >= totalSize };
    }
  } finally {
    try { reader.releaseLock(); } catch (_) {}
  }
}

// ── Resumable upload to Google Drive ──────────────────────────────
//
// Reliability model (kept deliberately simple for a personal project):
//   - A single window PUT that fails (network blip) is retried in
//     place, up to CFEC_MAX_CHUNK_RETRY times, re-sending only the
//     bytes Drive says it's still missing (probed via the standard
//     `Content-Range: bytes */total` status check) — no re-reading or
//     re-encrypting of the file is needed for this, common, case.
//   - If a chunk still can't get through (session likely dead), the
//     whole upload restarts from a fresh session and byte 0 — cheap,
//     because re-reading/re-encrypting a File from scratch costs
//     nothing but time, up to CFEC_MAX_FULL_RETRY attempts.
//   - A 401 mid-upload triggers `refreshAccessToken()` (re-hits the
//     Worker's /token endpoint) rather than failing outright, since a
//     very large upload over a slow link can outlast a token's life.
async function cfecResumableUploadToDrive({
  accessToken,
  refreshAccessToken,
  storedName,
  mimeType,
  totalSize,
  makeSourceStream, // () => ReadableStream<Uint8Array> of the full ciphertext, callable more than once
  onProgress,
  uploadWindow = CFEC_UPLOAD_WINDOW,
  maxChunkRetries = CFEC_MAX_CHUNK_RETRY,
  maxFullRetries = CFEC_MAX_FULL_RETRY,
}) {
  let token = accessToken;

  async function initSession() {
    const res = await fetch("https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json; charset=UTF-8",
        "X-Upload-Content-Type": mimeType,
        "X-Upload-Content-Length": String(totalSize),
      },
      body: JSON.stringify({ name: storedName, mimeType }),
    });
    if (res.status === 401 && refreshAccessToken) {
      token = await refreshAccessToken();
      return initSession();
    }
    if (!res.ok) throw new Error("Failed to start resumable upload session (HTTP " + res.status + ")");
    const loc = res.headers.get("Location");
    if (!loc) throw new Error("Drive did not return a resumable session URI");
    return loc;
  }

  async function queryUploadedOffset(sessionUri) {
    const res = await fetch(sessionUri, { method: "PUT", headers: { "Content-Range": `bytes */${totalSize}` } });
    if (res.status === 200 || res.status === 201) return { done: true, body: await res.json() };
    if (res.status === 308) {
      const range = res.headers.get("Range");
      const uploaded = range ? parseInt(range.split("-")[1], 10) + 1 : 0;
      return { done: false, offset: uploaded };
    }
    throw new Error("Could not query upload status (HTTP " + res.status + ")");
  }

  async function putWindowWithRetry(sessionUri, bytes, start) {
    let buf = bytes;
    let from = start;
    for (let attempt = 1; attempt <= maxChunkRetries; attempt++) {
      const end = from + buf.length - 1;
      try {
        const res = await fetch(sessionUri, {
          method: "PUT",
          headers: {
            "Authorization": `Bearer ${token}`,
            "Content-Length": String(buf.length),
            "Content-Range": `bytes ${from}-${end}/${totalSize}`,
          },
          body: buf,
        });
        if (res.status === 401 && refreshAccessToken) { token = await refreshAccessToken(); continue; }
        if (res.status === 308) return { done: false };
        if (res.status === 200 || res.status === 201) return { done: true, body: await res.json() };
        throw new Error("Unexpected status " + res.status + " uploading chunk");
      } catch (err) {
        if (attempt === maxChunkRetries) throw err;
        await cfecDelay(500 * attempt);
        try {
          const status = await queryUploadedOffset(sessionUri);
          if (status.done) return status;
          if (status.offset > from) { buf = buf.slice(status.offset - from); from = status.offset; }
          // else: Drive received nothing new — resend the same window as-is.
        } catch (_) { /* fall through and just retry with what we have */ }
      }
    }
  }

  async function attemptUpload() {
    const sessionUri   = await initSession();
    const cipherStream = makeSourceStream();
    let offset = 0;
    for await (const { bytes, isFinal } of cfecFixedWindows(cipherStream, uploadWindow, totalSize)) {
      const result = await putWindowWithRetry(sessionUri, bytes, offset);
      offset += bytes.length;
      onProgress?.(offset, totalSize);
      if (isFinal || result?.done) return result.body;
    }
    throw new Error("Upload stream ended before reaching the expected size");
  }

  let lastErr;
  for (let attempt = 1; attempt <= maxFullRetries; attempt++) {
    try {
      return await attemptUpload();
    } catch (err) {
      lastErr = err;
      if (attempt === maxFullRetries) break;
      console.warn(`Upload attempt ${attempt} failed, restarting from scratch:`, err);
      await cfecDelay(1000 * attempt);
    }
  }
  throw lastErr;
}

// ── Download side: streamed fetch -> streamed per-chunk decrypt ──
//
// `getKey(header)` is called once, as soon as the header has been
// parsed (before any chunk is decrypted), and must resolve to a
// CryptoKey, or to null to signal "user cancelled" (e.g. dismissed a
// password prompt) — which is reported as cancellation, not failure.
function cfecCreateDecryptTransform({ getKey }) {
  let buffer = new Uint8Array(0);
  let header = null;
  let key = null;
  let chunkIndex = 0;
  let bytesEmitted = 0;
  let stopped = false;

  return new TransformStream({
    async transform(bytes, controller) {
      if (stopped) return;
      buffer = cfecConcat(buffer, bytes);

      if (!header) {
        if (buffer.length < CFEC_HEADER_FIXED_LEN) return;
        const saltLen = buffer[26];
        const fullHeaderLen = CFEC_HEADER_FIXED_LEN + saltLen;
        if (buffer.length < fullHeaderLen) return;

        try {
          header = cfecDecodeHeader(buffer.slice(0, fullHeaderLen));
        } catch (e) {
          stopped = true; controller.error(e); return;
        }
        buffer = buffer.slice(fullHeaderLen);

        const k = await getKey(header);
        if (!k) { stopped = true; controller.error(new Error("CFEC_CANCELLED")); return; }
        key = k;
      }

      while (true) {
        if (stopped) return;
        if (buffer.length < 4) break;
        const len = new DataView(buffer.buffer, buffer.byteOffset, 4).getUint32(0, true);
        const recordLen = 4 + len;
        if (buffer.length < recordLen) break;
        const ciphertext = buffer.slice(4, recordLen);
        buffer = buffer.slice(recordLen);

        const plaintextLen = len - 16;
        const isLast = (bytesEmitted + plaintextLen) >= header.originalSize;
        const nonce  = cfecBuildNonce(header.noncePrefix, chunkIndex);
        const aad    = cfecBuildAAD(header.version, chunkIndex, isLast);

        let plain;
        try {
          plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, key, ciphertext);
        } catch (e) {
          stopped = true;
          controller.error(new Error(
            `Chunk ${chunkIndex} failed authentication — the file is corrupted, was tampered with, or the key/password is wrong.`
          ));
          return;
        }
        controller.enqueue(new Uint8Array(plain));
        bytesEmitted += plain.byteLength;
        chunkIndex++;
      }
    },
    flush(controller) {
      if (stopped) return;
      if (!header) { controller.error(new Error("File is truncated — could not read the encryption header")); return; }
      if (buffer.length > 0) { controller.error(new Error("File is truncated — incomplete trailing chunk")); return; }
      if (bytesEmitted !== header.originalSize) {
        controller.error(new Error(`Download incomplete: expected ${header.originalSize} bytes, got ${bytesEmitted}`));
      }
    },
  });
}
