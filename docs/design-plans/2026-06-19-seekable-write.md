# Seekable Write: Reproducible + Record-Addressable Encryption Design

## Summary

`@substrate-system/crypto-stream` implements RFC 8188 Encrypted Content
Encoding (ECE), a streaming cipher built on AES-GCM that divides plaintext into
fixed-size records and encrypts each one independently. This feature adds two
new capabilities to the library: **reproducible encryption**, where encrypting
the same content twice produces byte-identical ciphertext, and
**record-addressable encryption**, where any individual record can be encrypted
in isolation without processing the whole stream. Together these enable
efficient seekable access patterns — a consumer can request an arbitrary byte
range, compute which ECE record(s) it falls in, and regenerate or fetch only
those records.

The central engineering challenge is that reproducible encryption requires a
fixed salt, but AES-GCM's security model depends on each `(key, nonce)` pair
being used for exactly one plaintext. Reusing a salt with a different plaintext
would be catastrophic. The design solves this structurally rather than by
convention: the salt is never chosen by the caller. Instead it is derived from
a hash of the plaintext itself via HKDF (`salt = HKDF(key,
info="Content-Encoding: salt\0" || SHA-256(plaintext))`), so a given salt is
cryptographically bound to exactly one content. The public `Keychain` API
accepts a content digest and derives the salt internally, making the unsafe
pattern unreachable. Low-level raw-salt functions are exposed only via the
`./ece.js` subpath for advanced consumers. The implementation reuses existing
`ECETransformer` internals throughout, so no new cryptographic code is
introduced — byte-identical output with the streaming encoder is guaranteed by
sharing the same code path.

## Definition of Done

Library-only changes to `@substrate-system/crypto-stream` (the RFC 8188 ECE
layer). Consumer-side composition (Bao root computation, WebRTC seeding) is
out of scope.

**Safety model (the load-bearing decision).** Reproducible encryption requires
fixing the ECE content salt, which removes AES-GCM's per-call protection
against nonce reuse: the same `(key, salt)` encrypting two *different*
plaintexts collides record `seq` on the same `(content key, nonce)` —
catastrophic. To make this impossible rather than merely documented, the
deterministic salt is **never chosen by the caller**. It is derived from a
hash of the content via the key (`salt = HKDF(key, info="...salt\0"||digest)`).
Because the digest is collision-resistant over the plaintext, a salt cannot
pair with two different plaintexts. The consumer-facing `Keychain` API speaks
in *content digest* and never exposes a raw salt. Stateless cross-session
reproducibility is NOT a requirement (within-session reproduction — encrypt
once, regenerate records to match — is sufficient).

1. **Reproducible streaming encrypt.** `Keychain.encryptStream(stream, opts?)`
   accepts `{ contentDigest?, recordSize? }`. With a `contentDigest`, the salt
   is derived internally and two calls over identical input produce
   byte-for-byte identical ciphertext. With no opts, it keeps today's behavior
   (a fresh random salt per call; still round-trips). The Keychain API does not
   accept a raw salt.

2. **Record-addressable encrypt.** New low-level functions in `ece.ts`,
   reachable via the `./ece.js` subpath only (NOT re-exported from the root
   `index.ts`):
   - `recordPlaintextSize(rs?)`, `recordCount(plaintextSize, rs?)`
   - `header(salt, rs?)`
   - `deriveContentSalt(secretKey, contentDigest)` — HKDF, 16 bytes
   - `encryptRecord(secretKey, seq, plaintext, isLast, salt, rs?)`
   - newly-exported `RECORD_SIZE` and `HEADER_LENGTH`

   `encryptRecord` reuses the existing `ECETransformer` methods (`generateKey`,
   `generateNonceBase`, `encryptRecord`) so no new crypto is introduced, and it
   emits bytes byte-identical to record `seq` of the corresponding
   `encryptStream`. `ECETransformer.createHeader` delegates to the new `header`
   so the standalone header is byte-identical to the stream's header.

   Safe Keychain surface (speaks in content digest, salt stays internal):
   - `contentDigest(content)` — SHA-256 of plaintext (stream/Blob/Uint8Array),
     32 bytes
   - `header({ contentDigest, recordSize? })` — async (derives salt internally)
   - `encryptRecord(seq, plaintext, { isLast, contentDigest, recordSize? })`

3. **Defined edges.** `encryptRecord` strictly validates slice length:
   non-final records must equal `recordPlaintextSize(rs)`, the final record
   must be `<= recordPlaintextSize(rs)`; a violation throws. `recordCount(0)`
   returns `0`, consistent with `encryptStream` emitting only a header (no
   data records) for empty input.

4. **Proven by tests** (tapzero, `test/*.ts`):
   - Determinism: `contentDigest(x)` twice is equal; `encryptStream(x,
     { contentDigest })` twice produces identical bytes.
   - Content-binding: two different plaintexts yield different digests and
     therefore different `deriveContentSalt` outputs (the structural safety
     property, tested directly).
   - Record/stream equivalence: `header({ contentDigest, recordSize }) ||
     concat(encryptRecord(i, slice_i, { isLast, contentDigest, recordSize })
     for i in 0..recordCount-1)` equals the full `encryptStream(x,
     { contentDigest, recordSize })` output, byte for byte.
   - Round-trip: `decryptStream` of the per-record concatenation recovers the
     plaintext (decrypt reads the salt from the header, so it is agnostic to
     how the salt was derived).
   - Exact-multiple final-record padding: a plaintext whose length is an exact
     multiple of `recordPlaintextSize(rs)` still produces a valid final record.
   - Backward compat: `encryptStream(x)` with no opts uses a random salt and
     still round-trips.

## Acceptance Criteria

### seekable-write.AC1: Reproducible streaming encrypt
- **seekable-write.AC1.1 Success:** `encryptStream(x, { contentDigest })`
  called twice over identical input produces byte-identical ciphertext.
- **seekable-write.AC1.2 Success:** `encryptStream(x)` with no opts produces a
  different ciphertext on two calls (fresh random salt) and each round-trips
  via `decryptStream`.
- **seekable-write.AC1.3 Success:** `encryptStream(x, { recordSize: rs })`
  places record boundaries at `rs` (output length equals
  `encryptedSize(len, rs)`).
- **seekable-write.AC1.4 Edge:** `encryptStream` of empty input emits only the
  21-byte header.

### seekable-write.AC2: Content-derived salt safety
- **seekable-write.AC2.1 Success:** `contentDigest(x)` returns a stable 32-byte
  value (same input yields the same digest).
- **seekable-write.AC2.2 Success:** two different plaintexts yield different
  digests and therefore different `deriveContentSalt` outputs.
- **seekable-write.AC2.3 Success:** `deriveContentSalt(key, digest)` is
  deterministic for the same `(key, digest)`.
- **seekable-write.AC2.4 Success:** `contentDigest` accepts `ReadableStream`,
  `Uint8Array`, and `Blob`, producing the same digest for equivalent content.

### seekable-write.AC3: Record/stream equivalence
- **seekable-write.AC3.1 Success:** `header(salt, rs)` equals the first 21
  bytes of `encryptStream` output for the same salt and rs.
- **seekable-write.AC3.2 Success:** `header(salt, rs) || concat(encryptRecord(i,
  slice_i, isLast))` equals a full `encryptStream(x, rs, salt)`, byte for byte.
- **seekable-write.AC3.3 Success:** `decryptStream` of that per-record
  concatenation recovers the original plaintext.
- **seekable-write.AC3.4 Success:** the same round-trip holds through the
  Keychain digest API (`keychain.header(...)` + `keychain.encryptRecord(...)`).

### seekable-write.AC4: Record geometry and edges
- **seekable-write.AC4.1 Success:** `recordPlaintextSize(rs)` equals `rs - 17`
  (and for the default record size).
- **seekable-write.AC4.2 Success:** `recordCount(n, rs)` equals
  `ceil(n / (rs - 17))` for `n > 0`.
- **seekable-write.AC4.3 Edge:** `recordCount(0) === 0`.
- **seekable-write.AC4.4 Edge:** a plaintext of length exactly `k*(rs - 17)`
  produces `k` records with a valid full final record.

### seekable-write.AC5: Validation
- **seekable-write.AC5.1 Failure:** `encryptRecord` with a non-final slice whose
  length differs from `recordPlaintextSize(rs)` throws.
- **seekable-write.AC5.2 Failure:** `encryptRecord` with a final slice longer
  than `recordPlaintextSize(rs)` throws.
- **seekable-write.AC5.3 Failure:** `deriveContentSalt` with an empty digest
  throws.
- **seekable-write.AC5.4 Failure:** a non-16-byte salt passed to a low-level
  `ece` function throws `Invalid salt length`.

### seekable-write.AC6: Export surface (cross-cutting)
- **seekable-write.AC6.1 Success:** `RECORD_SIZE`, `HEADER_LENGTH`,
  `recordPlaintextSize`, `recordCount`, `header`, `deriveContentSalt`, and
  `encryptRecord` are importable from the `./ece.js` subpath.
- **seekable-write.AC6.2 Success:** the root `index.ts` export surface gains
  none of these names (the curated root export is unchanged).

## Glossary

- **AES-GCM**: A symmetric authenticated encryption scheme. The "GCM" mode
  produces both ciphertext and an authentication tag that detects tampering.
  Used here to encrypt each ECE record.
- **Bao**: A content-addressed, incrementally verifiable hash tree for byte
  streams. Referenced in the data-flow section as the consumer-side mechanism
  for computing a verifiable root over the ciphertext; out of scope for this
  library.
- **content digest**: A SHA-256 hash of the plaintext, used as the input to
  salt derivation. The `Keychain` API accepts this instead of a raw salt so
  that the salt is always content-bound.
- **content key**: The per-stream AES key derived from the secret key and salt
  by HKDF. Each ECE record's nonce is further derived from the content key and
  the record sequence number.
- **deriveContentSalt**: The HKDF-based function that maps
  `(secretKey, contentDigest)` to a deterministic 16-byte salt. Its info string
  (`Content-Encoding: salt\0`) separates it from the existing content-key and
  nonce derivations.
- **ECE (Encrypted Content Encoding)**: RFC 8188, a standard for encrypting
  HTTP content in fixed-size records. Defines the binary format: a 21-byte
  header (salt, record size, key-id length) followed by a sequence of encrypted
  records each ending with a one-byte padding delimiter.
- **ECETransformer**: The existing internal class in `src/ece.ts` that
  implements the RFC 8188 streaming encoder/decoder as a WHATWG
  `TransformStream`. The new per-record functions drive it through its existing
  methods rather than re-implementing the crypto.
- **HKDF**: HMAC-based Key Derivation Function (RFC 5869). Used here to derive
  the content key, nonce base, and (new) content salt from the main secret key,
  each separated by a distinct `info` string.
- **`info` string**: The label parameter in an HKDF call. Different info strings
  derive independent keys from the same root material, preventing one derived
  value from revealing another.
- **Keychain**: The existing high-level class in `src/keychain.ts` that manages
  a master secret key and exposes safe encrypt/decrypt methods. The
  consumer-facing API added by this feature lives here.
- **nonce reuse**: Using the same `(key, nonce)` pair to encrypt two different
  plaintexts under AES-GCM. This is catastrophic — an attacker can recover the
  XOR of the two plaintexts and forge authentication tags. The design prevents
  it structurally by binding the salt (and therefore every nonce) to a specific
  plaintext.
- **record**: The fundamental unit of ECE encryption. A record is a fixed-size
  slice of plaintext (default 65536 − 17 = 65519 bytes) plus a one-byte padding
  delimiter, encrypted to a fixed-size ciphertext block. Records can be
  decrypted independently given the salt and sequence number.
- **record-addressable**: The ability to encrypt or decrypt an individual
  record by index (`seq`) without processing preceding records. Enabled here by
  the new `encryptRecord` function.
- **reproducible encryption**: Encrypting the same plaintext twice and obtaining
  byte-identical ciphertext. Requires a deterministic salt, which this design
  derives from the content digest.
- **salt**: A 16-byte random (or deterministic) value included in the ECE
  header. Combined with the secret key via HKDF to produce the per-stream
  content key. Fixing the salt makes encryption reproducible; deriving it from
  the content digest keeps it safe.
- **seq / sequence number**: The zero-based index of a record within a stream.
  Combined with the nonce base to form the unique AES-GCM nonce for that record.
- **SHA-256**: A cryptographic hash function. Used here to compute the content
  digest over the plaintext. Collision-resistance is what makes the
  salt-binding safety argument hold.
- **subpath export (`./ece.js`)**: A Node.js/bundler package.json `exports`
  field entry that exposes a secondary entry point from the same package. Used
  here to make low-level raw-salt functions importable without polluting the
  root `index.ts` surface.
- **TAG_LENGTH**: The 16-byte AES-GCM authentication tag appended to each
  encrypted record. Together with the 1-byte padding delimiter, this accounts
  for the 17 bytes of overhead per record (`recordPlaintextSize = rs − 17`).
- **tapzero**: The test harness used by this library
  (`@substrate-system/tapzero`), a minimal TAP-producing test runner for
  TypeScript.
- **two-pass**: The processing pattern required for reproducible mode: first
  stream the content through `contentDigest` to obtain the SHA-256 hash, then
  stream it again through `encryptStream` (now able to derive the salt). Both
  passes stream without buffering the full content.
- **WebRTC seeding**: Mentioned in scope exclusions; refers to using the
  reproduced ciphertext records to seed data to WebRTC peers. Out of scope for
  this library.

## Architecture

Two files change; no new dependencies and no new cryptographic primitives. The
work splits into a low-level layer (`src/ece.ts`) and a safe consumer-facing
layer (`src/keychain.ts`).

**Low-level (`src/ece.ts`, reachable via the `./ece.js` subpath).** Promote
`RECORD_SIZE` and `HEADER_LENGTH` to exports. Add pure geometry helpers
(`recordPlaintextSize`, `recordCount`), a canonical header builder (`header`),
a salt derivation (`deriveContentSalt`), and a single-record encrypt
(`encryptRecord`). `encryptRecord` drives an `ECETransformer` instance through
its existing `generateKey` / `generateNonceBase` / `encryptRecord` methods, so
the AES-GCM, padding, nonce, and (empty) AAD path is shared with the streaming
encoder by construction — that shared path is what guarantees byte-identical
output. `ECETransformer.createHeader` is refactored to delegate to the new
`header`, making the standalone header byte-identical to the stream's header.
These low-level functions take a raw salt; they are the building blocks, not
the recommended surface.

**Safe surface (`src/keychain.ts`).** The consumer-facing API speaks in
*content digest*, never a raw salt. `contentDigest(content)` computes SHA-256
over the plaintext (stream / Blob / Uint8Array). `encryptStream` gains
`{ contentDigest?, recordSize? }`; given a digest it derives the salt
internally via `deriveContentSalt(mainKey, digest)` and produces reproducible
output, and with no opts it keeps today's random-salt behavior. `header` and
`encryptRecord` methods take `{ contentDigest, ... }` and derive the same salt
internally on each call. Because `salt = f(mainKey, contentDigest)` and the
digest is collision-resistant over the plaintext, a salt can never pair with
two different plaintexts — the AES-GCM nonce-reuse failure mode is structurally
unreachable from the Keychain API. `this.salt` continues to serve only the
metadata key and auth token, unchanged.

**Data flow (consumer, for context — out of scope to build).** (1) Hash pass:
`digest = await keychain.contentDigest(file.stream())`. (2) Encrypt pass:
`keychain.encryptStream(file.stream(), { contentDigest: digest, recordSize:
rs })`, over which the consumer computes its Bao root. (3) On demand:
`keychain.encryptRecord(i, slice_i, { isLast, contentDigest: digest,
recordSize: rs })` regenerates record `i` byte-identically, with the salt
re-derived internally from the same digest. The full ciphertext is
`header(21) || rec0 || rec1 || … || recLast`.

## Existing Patterns

This design follows patterns already established in the library.

- **Symmetric to the read side.** The library already ships
  `decryptStreamRange` (and `Keychain.decryptStreamRange`) for record-granular
  *reads*. This design adds the symmetric *write* side (per-record encrypt),
  intentionally as a simpler "give me record `i`" primitive rather than a
  byte-range shape — there is no cross-record state on the write side.
- **Reuse, don't duplicate, the crypto.** `encryptRecord` reuses
  `ECETransformer`'s existing methods rather than re-deriving HKDF/AES-GCM,
  matching the library's existing single-source-of-truth approach and
  guaranteeing byte-identical output.
- **HKDF info-string separation.** The codebase already derives independent
  keys from one key/salt using distinct `info` strings (`Content-Encoding:
  aes128gcm\0`, `Content-Encoding: nonce\0`, `metadata`, `authentication`).
  `deriveContentSalt` adds another (`Content-Encoding: salt\0`), staying within
  this pattern.
- **Validation style.** `recordPlaintextSize` / `recordCount` mirror the
  `Number.isInteger` guards used by the existing `encryptedSize` /
  `plaintextSize` helpers.
- **Tests.** `@substrate-system/tapzero` with `test('name', async t => …)` in
  `test/*.ts`, imported from `test/index.ts`.

## Implementation Phases

<!-- START_PHASE_1 -->
### Phase 1: Record geometry and canonical header (`ece.ts`)
**Goal:** Expose record geometry and a single canonical header builder shared
with the streaming encoder.

**Components:**
- `src/ece.ts` — change `RECORD_SIZE` and `HEADER_LENGTH` from module-private
  `const` to `export const`.
- `src/ece.ts` — `recordPlaintextSize(rs?)` returns `rs - TAG_LENGTH - 1`;
  `recordCount(plaintextSize, rs?)` returns `ceil(plaintextSize /
  recordPlaintextSize(rs))` (so `recordCount(0) === 0`, NOT `Math.max(1, …)`);
  both guard inputs with `Number.isInteger`.
- `src/ece.ts` — `header(salt, rs?)` builds the 21-byte header
  (`salt(16) || rs(uint32 BE) || idlen(0)`); refactor
  `ECETransformer.createHeader` to delegate to it.
- `test/seekable-write.ts` (new, imported from `test/index.ts`).

**Dependencies:** None.

**Done when:** Geometry helpers return correct values including the empty case
(`recordCount(0) === 0`); `header(salt, rs)` equals the first 21 bytes that
`encryptStream` emits for the same salt/rs. Covers `seekable-write.AC4`,
`seekable-write.AC6`.
<!-- END_PHASE_1 -->

<!-- START_PHASE_2 -->
### Phase 2: Content salt + single-record encrypt (`ece.ts`)
**Goal:** Derive a content-bound salt and encrypt one record byte-identically
to the stream.

**Components:**
- `src/ece.ts` — `deriveContentSalt(secretKey, contentDigest)`: HKDF-SHA256
  with `info = "Content-Encoding: salt\0" || contentDigest`, returning 16
  bytes. Pure function of `(secretKey, contentDigest)`.
- `src/ece.ts` — `encryptRecord(secretKey, seq, plaintext, isLast, salt, rs?)`:
  instantiate `ECETransformer(MODE_ENCRYPT, secretKey, rs, salt)` (which
  validates key and salt length), set `key`/`nonceBase` via the existing
  `generateKey`/`generateNonceBase`, strictly validate the slice length
  (non-final must equal `recordPlaintextSize(rs)`, final must be `<=`; else
  throw), then call the existing `encryptRecord` method.

**Dependencies:** Phase 1 (`recordPlaintextSize`, `header`).

**Done when:** `header(salt, rs) || concat(encryptRecord(i, slice_i, isLast))`
equals a full `encryptStream(x, rs, salt)` byte for byte (including the
exact-multiple case where the final record is a full `rs-17` slice); a
wrong-sized non-final slice throws; two different digests produce different
salts. Covers `seekable-write.AC2`, `seekable-write.AC3`, `seekable-write.AC5`.
<!-- END_PHASE_2 -->

<!-- START_PHASE_3 -->
### Phase 3: Keychain digest + reproducible stream (`keychain.ts`)
**Goal:** Add the content-digest helper and make `encryptStream` reproducible
without exposing a raw salt.

**Components:**
- `src/keychain.ts` — `contentDigest(content)`: SHA-256 over
  `ReadableStream<Uint8Array> | Uint8Array | Blob`, returning 32 bytes
  (streams/Blobs hashed without buffering the whole plaintext into one array
  where the platform allows).
- `src/keychain.ts` — change `encryptStream(stream, opts?)` to accept
  `{ contentDigest?, recordSize? }`; when `contentDigest` is present derive the
  salt via `deriveContentSalt(mainKey, contentDigest)` and pass it to
  `ece.encryptStream`; otherwise preserve today's random-salt behavior.

**Dependencies:** Phase 2 (`deriveContentSalt`).

**Done when:** `encryptStream(x, { contentDigest })` is byte-identical across
calls; `contentDigest(x)` is stable and differs for different plaintext;
`encryptStream(x)` with no opts still uses a random salt and round-trips.
Covers `seekable-write.AC1`, `seekable-write.AC2`.
<!-- END_PHASE_3 -->

<!-- START_PHASE_4 -->
### Phase 4: Keychain record methods (`keychain.ts`)
**Goal:** Expose the safe, digest-based record surface and prove round-trip.

**Components:**
- `src/keychain.ts` — `header({ contentDigest, recordSize? })` (async; derives
  salt then calls `ece.header`).
- `src/keychain.ts` — `encryptRecord(seq, plaintext, { isLast, contentDigest,
  recordSize? })` (derives salt then calls `ece.encryptRecord`).

**Dependencies:** Phase 2 (`ece.encryptRecord`, `ece.header`), Phase 3
(`contentDigest`).

**Done when:** `decryptStream` of `keychain.header(...) ||
concat(keychain.encryptRecord(i, slice_i, …))` recovers the original plaintext;
an empty plaintext yields header-only output and `recordCount(0) === 0` holds
end to end. Covers `seekable-write.AC3`, `seekable-write.AC4`.
<!-- END_PHASE_4 -->

<!-- START_PHASE_5 -->
### Phase 5: Documentation
**Goal:** Document the safety model and the new surface.

**Components:**
- `README.md` — a section on reproducible / record-addressable encryption: the
  content-digest model, the two-pass (hash then encrypt) flow, and that the
  `ece.js` raw-salt functions are low-level building blocks.
- JSDoc on `contentDigest`, `encryptStream`, `header`, `encryptRecord`,
  `deriveContentSalt`, and `encryptRecord` (ece) stating that a fixed salt must
  never encrypt two different plaintexts, which is why the salt is derived from
  the content and the Keychain API does not accept a raw salt.

**Dependencies:** Phases 1-4.

**Done when:** README documents the model and flow; public additions carry
JSDoc. Verified operationally (docs present, `npm run lint` passes).
<!-- END_PHASE_5 -->

## Additional Considerations

**Error handling.** Validation fails loudly and early: `encryptRecord` throws
on a wrong-sized slice; the reused `ECETransformer` constructor throws on a bad
key (`checkSecretKey`) or non-16-byte salt; `generateNonce` throws when
`seq > 0xffffffff`. `deriveContentSalt` requires a non-empty digest.

**Edge cases.** Empty input produces header-only output (the `SliceTransformer`
emits no chunks, so `ECETransformer` enqueues only the header), matched by
`recordCount(0) === 0`. A plaintext that is an exact multiple of
`recordPlaintextSize(rs)` yields a full final record (`rs-17` bytes plus the
`0x02` delimiter), which `pad` accepts.

**Two passes.** Reproducible mode requires hashing the plaintext before
encrypting it (the salt depends on the digest), so the consumer streams the
content twice. This is an accepted cost of structural safety; both passes
stream without buffering. Random (non-reproducible) `encryptStream` remains a
single pass.

**Surface split.** The `ece.js` raw-salt functions remain available for
advanced use (e.g. supplying an externally computed content id as the digest,
or amortizing salt derivation across many records), but they are documented as
low-level. The Keychain API is the supported, footgun-free surface.
