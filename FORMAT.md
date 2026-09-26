# CFEC — Chunked File Encryption Container

Binary format used for every file uploaded through the chunked streaming
pipeline (`crypto-stream.js`). This is the file's *own* content as stored in
Google Drive — it is completely separate from the small JSON metadata record
kept in the Worker's KV store (filename, size, mime type, etc.).

Goal: a decoder should be able to tell, from the bytes alone, exactly how to
decrypt the file — chunk size, total size, and KDF parameters travel with the
file rather than being assumed by the code reading it. That's what lets the
format change in the future (a `version` bump) without breaking files
uploaded under an older version.

## Header

All multi-byte integers are little-endian.

| Offset | Length | Field         | Notes                                             |
|-------:|-------:|---------------|----------------------------------------------------|
|      0 |      4 | magic         | ASCII `"CFEC"`                                     |
|      4 |      1 | version       | currently `1`                                      |
|      5 |      1 | flags         | bit0: `1` = password/PBKDF2 mode, `0` = raw key    |
|      6 |      4 | chunkSize     | uint32, plaintext bytes per chunk (last may be less) |
|     10 |      8 | originalSize  | uint64, total plaintext bytes                      |
|     18 |      4 | noncePrefix   | random per file, see **Nonces** below              |
|     22 |      4 | kdfIterations | uint32, PBKDF2 iteration count (`0` if not password mode) |
|     26 |      1 | saltLen       | `16` if password mode, else `0`                    |
|     27 |  saltLen | salt        | PBKDF2 salt (absent if `saltLen == 0`)             |

## Chunk records

Immediately after the header, one record per chunk, back to back, nothing
after the last one:

| Offset | Length         | Field         |
|-------:|---------------:|---------------|
|      0 |              4 | ciphertextLen | uint32, includes the 16-byte GCM tag |
|      4 | ciphertextLen  | ciphertext    | AES-256-GCM output (tag appended)    |

A zero-byte source file still produces exactly one record (an
all-tag, zero-plaintext chunk), so every valid container has at least one
record.

## Nonces

Rather than storing a 12-byte nonce per chunk, it's derived deterministically:

```
nonce = noncePrefix (4 bytes, from header) || chunkIndex (8 bytes, big-endian, 0-based)
```

The counter never repeats within a file, so every chunk gets a unique nonce
under the same key without needing 96 bits of luck — important once a large
file produces thousands of chunks.

## Authenticated data

Each chunk's AES-GCM call binds 10 bytes of additional authenticated data:

```
AAD = version (1 byte) || chunkIndex (8 bytes, big-endian) || isLastChunk (1 byte: 0/1)
```

This means a chunk's tag only verifies if it's decrypted at the position (and
finality) it was originally encrypted at — reordering or splicing chunks
between files (even ones sharing a key) is caught, not just bit-flips within
one chunk.

## Detecting truncation

The header's `originalSize` is known before decryption starts. A decoder
must verify, once the stream ends, that:

- the total plaintext produced across all chunks equals `originalSize`, and
- there are no leftover, incomplete bytes after the last full chunk record.

Either check failing means the download was cut short (or tampered with) —
see the `flush()` step of `cfecCreateDecryptTransform` in `crypto-stream.js`.

## Sizing a container up front

Because `chunkSize` is fixed for all but the final chunk, the exact
ciphertext size is computable before encrypting a single byte — this is what
lets the upload path tell Google Drive the exact final size of a resumable
upload session from the very first request:

```
numChunks = originalSize == 0 ? 1 : ceil(originalSize / chunkSize)
totalSize = headerLen + numChunks * (4 + 16) + originalSize
```

## Compatibility

Files uploaded before this format existed have no `formatVersion` field in
their KV metadata at all; the client detects that and falls back to the old
whole-buffer decrypt path (`downloadFileLegacy` in `app.js`). They are never
re-encoded — this format only applies going forward.
