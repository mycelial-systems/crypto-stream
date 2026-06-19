# Seekable Write Implementation Plan — Phase 2

**Goal:** Derive a content-bound salt and encrypt a single ECE record
byte-identically to the corresponding record in the stream.

**Architecture:** Add `deriveContentSalt` (HKDF over the secret key with a new
`info` string plus the content digest) and `encryptRecord` (drives an
`ECETransformer` instance through its existing `generateKey`/`generateNonceBase`/
`encryptRecord` methods). No new cryptographic code — byte-identical output is
guaranteed by reusing the same code path as the streaming encoder.

**Tech Stack:** TypeScript (ESM), WebCrypto (`@substrate-system/one-webcrypto`,
already a dependency), tapzero tests.

**Scope:** Phase 2 of 5 (Content salt + single-record encrypt).

**Codebase verified:** 2026-06-19

**Style rules:** See Phase 1 ("Style rules"). Match existing `src/ece.ts`: no
space before type annotations, `function` declarations, throw `Error`/
`TypeError`, 80-column wrap.

---

## Acceptance Criteria Coverage

This phase implements and tests:

### seekable-write.AC2: Content-derived salt safety
- **seekable-write.AC2.2 Success:** two different plaintexts yield different
  digests and therefore different `deriveContentSalt` outputs. *(This phase
  proves the salt half: two different digest values produce different salts.
  The "different plaintexts → different digests" half is completed in Phase 3
  via `contentDigest`.)*
- **seekable-write.AC2.3 Success:** `deriveContentSalt(key, digest)` is
  deterministic for the same `(key, digest)`.

### seekable-write.AC3: Record/stream equivalence
- **seekable-write.AC3.2 Success:** `header(salt, rs) || concat(encryptRecord(i,
  slice_i, isLast))` equals a full `encryptStream(x, rs, salt)`, byte for byte.
- **seekable-write.AC3.3 Success:** `decryptStream` of that per-record
  concatenation recovers the original plaintext.

### seekable-write.AC4: Record geometry and edges
- **seekable-write.AC4.4 Edge:** a plaintext of length exactly `k*(rs - 17)`
  produces `k` records with a valid full final record. *(This phase completes
  AC4.4: the exact-multiple case yields a valid full final record, proven via
  AC3.2 equivalence on exact-multiple input.)*

### seekable-write.AC5: Validation
- **seekable-write.AC5.1 Failure:** `encryptRecord` with a non-final slice whose
  length differs from `recordPlaintextSize(rs)` throws.
- **seekable-write.AC5.2 Failure:** `encryptRecord` with a final slice longer
  than `recordPlaintextSize(rs)` throws.
- **seekable-write.AC5.3 Failure:** `deriveContentSalt` with an empty digest
  throws.
- **seekable-write.AC5.4 Failure:** a non-16-byte salt passed to a low-level
  `ece` function throws `Invalid salt length`.

### seekable-write.AC6: Export surface
- **seekable-write.AC6.1 Success (completion):** extend the Phase 1 export test
  so `deriveContentSalt` and `encryptRecord` are also importable from
  `'../src/ece.js'`.

---

## Context the engineer needs

- `ECETransformer` constructor (`src/ece.ts:34-67`) signature is
  `(mode, secretKey, rs, salt, seekOpts = {})`. It validates, in order: mode,
  `checkSecretKey(secretKey)`, then `if (salt != null && salt.byteLength !==
  KEY_LENGTH) throw new Error('Invalid salt length')` (`src/ece.ts:47-49`). For
  `encryptRecord` we always pass a real 16-byte salt, so a wrong-length salt
  throws `Invalid salt length` here.

- `generateKey` (`src/ece.ts:69-85`) and `generateNonceBase`
  (`src/ece.ts:87-99`) **return** their values; the transformer's `start()`
  assigns them: `this.key = await this.generateKey()` and `this.nonceBase =
  await this.generateNonceBase()` (`src/ece.ts:224-225`). A standalone record
  encrypt must set both instance fields the same way before calling
  `encryptRecord`.

- The instance method `encryptRecord(record, seq, isLast)` (`src/ece.ts:178-199`)
  calls `this.generateNonce(seq)`, `this.pad(record, isLast)`, then AES-GCM
  `encrypt` with `this.key`. `pad` (`src/ece.ts:115-133`) appends a single
  `0x02` byte for the last record, or fills to `rs - len - TAG_LENGTH` bytes
  with a leading `0x01` for non-final records. For a non-final record this only
  produces the correct single `0x01` delimiter when `len === rs - 17`; hence the
  strict non-final length check below.

- The streaming encoder (`src/ece.ts:366-381`) slices input with
  `new SliceTransformer(rs - TAG_LENGTH - 1)` (= `rs - 17`), then encrypts each
  slice with `seq = 0, 1, 2, …`, marking the final slice `isLast`. The header is
  `createHeader()` → `header(salt, rs)` (Phase 1). So `header(salt, rs)` followed
  by `encryptRecord(i, slice_i, isLast)` for `i = 0 … recordCount-1` reproduces
  the full stream byte-for-byte.

- Existing HKDF info strings (`src/ece.ts:75,93`):
  `'Content-Encoding: aes128gcm\0'` (content key) and `'Content-Encoding:
  nonce\0'` (nonce base), both via `encoder.encode(...)` where
  `encoder = new TextEncoder()` (`src/ece.ts:21`). `deriveContentSalt` adds a
  third independent label: `'Content-Encoding: salt\0'`.

- WebCrypto HKDF (`webcrypto.subtle.deriveBits`) requires a `salt` field in the
  algorithm object. For `deriveContentSalt` there is no salt yet (we are deriving
  one), so pass an empty `new Uint8Array(0)`. Per RFC 5869, an absent/empty HKDF
  salt is treated as zeros; HMAC zero-pads a short key to the block size, so an
  empty salt is well-defined and deterministic. (If a target runtime ever
  rejects an empty salt, the fallback is a fixed 32-byte zero salt — but Node 18+
  and browsers accept the empty salt.)

- `MODE_ENCRYPT` (`src/ece.ts:13`) and `ECETransformer` are module-private but in
  the same file, so the new functions reference them directly.

---

<!-- START_SUBCOMPONENT_B (tasks 1-3) -->

<!-- START_TASK_1 -->
### Task 1: Add deriveContentSalt

**Verifies:** seekable-write.AC2.2 (salt half), seekable-write.AC2.3,
seekable-write.AC5.3

**Files:**
- Modify: `src/ece.ts` (add near the other exported functions, e.g. after
  `header` from Phase 1)
- Test: `test/seekable-write.ts`

**Implementation:**
HKDF-SHA256 over the secret key, with `info = "Content-Encoding: salt\0" ||
contentDigest`, returning 16 bytes. Pure function of `(secretKey,
contentDigest)`. Reject an empty digest.

```ts
const SALT_INFO = encoder.encode('Content-Encoding: salt\0')

/**
 * Derive a deterministic 16-byte content salt from the secret key and a
 * content digest, via HKDF-SHA256 with info
 * `"Content-Encoding: salt\0" || contentDigest`.
 *
 * Because the digest is collision-resistant over the plaintext, a salt is
 * cryptographically bound to exactly one content — so a fixed salt can never
 * pair with two different plaintexts. This is what makes reproducible
 * encryption safe under AES-GCM (no nonce reuse across distinct plaintexts).
 *
 * @param secretKey HKDF CryptoKey (the main secret key).
 * @param contentDigest Digest of the plaintext (e.g. 32-byte SHA-256).
 * @returns 16-byte content salt.
 */
export async function deriveContentSalt (
    secretKey:CryptoKey,
    contentDigest:Uint8Array
):Promise<Uint8Array<ArrayBuffer>> {
    if (contentDigest.byteLength === 0) {
        throw new Error('empty content digest')
    }

    const info = new Uint8Array(SALT_INFO.byteLength + contentDigest.byteLength)
    info.set(SALT_INFO, 0)
    info.set(contentDigest, SALT_INFO.byteLength)

    const bits = await webcrypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new Uint8Array(0),
            info
        },
        secretKey,
        KEY_LENGTH * 8
    )

    return new Uint8Array(bits)
}
```

Place `SALT_INFO` at module scope alongside `encoder` (`src/ece.ts:21`) or
immediately above `deriveContentSalt`.

**Testing:**
In `test/seekable-write.ts`:
- seekable-write.AC2.3: `deriveContentSalt(key, digest)` called twice with the
  same `(key, digest)` returns equal 16-byte arrays (`t.deepEqual`,
  `t.equal(salt.byteLength, 16)`). Build `key` via the `makeKey` helper; use any
  fixed 32-byte `digest` (e.g. `new Uint8Array(32).fill(7)`).
- seekable-write.AC2.2 (salt half): two different digest values
  (`new Uint8Array(32).fill(1)` vs `.fill(2)`) under the same key produce
  different salts (assert NOT `deepEqual`; compare via a byte-equality check or
  base64).
- seekable-write.AC5.3: `deriveContentSalt(key, new Uint8Array(0))` rejects
  (async). tapzero's `t.throws` is async-aware (it awaits the function), so
  `await t.throws(async () => deriveContentSalt(key, new Uint8Array(0)))` is the
  cleanest form; a try/catch + `t.ok(err)` is equally acceptable.

**Verification:**
Run: `npm test`
Expected: determinism, content-binding, and empty-digest tests pass.

**Commit:** `feat(ece): add deriveContentSalt (content-bound HKDF salt)`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Add encryptRecord (single-record encrypt)

**Verifies:** seekable-write.AC5.1, seekable-write.AC5.2, seekable-write.AC5.4

**Files:**
- Modify: `src/ece.ts` (add after `deriveContentSalt`)
- Test: `test/seekable-write.ts`

**Implementation:**
Encrypt one record byte-identically to record `seq` of the stream. Instantiate
an `ECETransformer` (which validates the key and salt length), strictly validate
the slice length, set `key`/`nonceBase` via the existing methods, then delegate
to the instance `encryptRecord`.

```ts
/**
 * Encrypt a single ECE record in isolation, byte-identical to record `seq` of
 * the corresponding `encryptStream` output. Drives an `ECETransformer` through
 * its existing key/nonce/record methods, so no new crypto is introduced.
 *
 * Non-final records must be exactly `recordPlaintextSize(rs)` bytes; the final
 * record must be `<= recordPlaintextSize(rs)` bytes.
 *
 * SAFETY: the same `(secretKey, salt)` must never encrypt two different
 * plaintexts (AES-GCM nonce reuse). This low-level function takes a raw salt;
 * derive it from the content via `deriveContentSalt`, or use the Keychain API,
 * which never exposes a raw salt.
 *
 * @param secretKey HKDF CryptoKey (the main secret key).
 * @param seq Zero-based record index.
 * @param plaintext The record's plaintext slice.
 * @param isLast Whether this is the final record.
 * @param salt 16-byte content salt (same salt as the stream's header).
 * @param rs Record size in bytes (default RECORD_SIZE).
 * @returns The encrypted record bytes.
 */
export async function encryptRecord (
    secretKey:CryptoKey,
    seq:number,
    plaintext:Uint8Array,
    isLast:boolean,
    salt:Uint8Array<ArrayBuffer>,
    rs:number = RECORD_SIZE
):Promise<Uint8Array> {
    // Validates the key and the salt length (throws 'Invalid salt length').
    const transformer = new ECETransformer(MODE_ENCRYPT, secretKey, rs, salt)

    const max = recordPlaintextSize(rs)
    if (isLast) {
        if (plaintext.byteLength > max) {
            throw new Error('final record exceeds recordPlaintextSize')
        }
    } else {
        if (plaintext.byteLength !== max) {
            throw new Error('non-final record must equal recordPlaintextSize')
        }
    }

    transformer.key = await transformer.generateKey()
    transformer.nonceBase = await transformer.generateNonceBase()

    return transformer.encryptRecord(plaintext, seq, isLast)
}
```

Note: the constructor validates the salt length BEFORE the slice-length check,
so a 15-byte salt throws `Invalid salt length` (AC5.4) regardless of slice size.

**Testing:**
In `test/seekable-write.ts`:
  (`t.throws` is async-aware — `await t.throws(async () => …)` — and accepts a
  `RegExp` matcher; a try/catch + `t.ok(err)` is equally fine.)
- seekable-write.AC5.1: a non-final slice with length `!= recordPlaintextSize(rs)`
  (e.g. `max - 1` with `isLast = false`) rejects.
- seekable-write.AC5.2: a final slice with length `> recordPlaintextSize(rs)`
  (e.g. `max + 1` with `isLast = true`) rejects.
- seekable-write.AC5.4: `encryptRecord(key, 0, slice, true, new Uint8Array(15),
  rs)` rejects with a message containing `Invalid salt length` — assert the
  message with the `RegExp` matcher, e.g. `await t.throws(async () =>
  encryptRecord(key, 0, slice, true, new Uint8Array(15), rs),
  /Invalid salt length/)`. (Also acceptable: assert the same via
  `header(new Uint8Array(15))` since both are low-level ece functions; either
  satisfies AC5.4.)

Use a small `rs` (e.g. 64) so `max = rs - 17 = 47` keeps slices tiny.

**Verification:**
Run: `npm test`
Expected: all validation tests pass.

**Commit:** `feat(ece): add encryptRecord (record-addressable encrypt)`
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Record/stream equivalence and round-trip tests

**Verifies:** seekable-write.AC3.2, seekable-write.AC3.3, seekable-write.AC4.4
(final record), seekable-write.AC6.1 (completion)

**Files:**
- Modify: `test/seekable-write.ts`
- (No `src/` changes — this proves Tasks 1-2 against the stream.)

**Implementation (test-only):**
Add a reusable helper that rebuilds a full ciphertext from per-record encrypts,
then assert it matches the stream and decrypts back to the plaintext.

Build the per-record ciphertext as:
`header(salt, rs)` concatenated with, for each `i` in `0 … recordCount(len,
rs) - 1`, `encryptRecord(key, i, slice_i, isLast_i, salt, rs)`, where `slice_i`
is `plaintext.subarray(i * max, (i + 1) * max)`, `max = recordPlaintextSize(rs)`,
and `isLast_i` is `i === recordCount - 1`. Concatenate the pieces into one
`Uint8Array`.

**Testing:**
- seekable-write.AC3.2: for several plaintext lengths, assert the per-record
  ciphertext equals `streamToArray(encryptStream(arrayToStream(plaintext), key,
  rs, salt))` byte-for-byte (`t.deepEqual`). Cover at least:
  - a length that is NOT a multiple of `max` (partial final record),
  - a single full record (`len === max`),
  - a multi-record non-multiple length.
  Use the SAME `key` and fixed `salt` for both sides. Use a small `rs` (e.g.
  256) so multiple records are exercised cheaply.
- seekable-write.AC4.4 (final record): include a plaintext of length exactly
  `k * max` (e.g. `k = 3`) in the AC3.2 assertion. This proves the exact-multiple
  case produces `k` records with a valid full final record (the per-record build
  marks slice `k-1` as `isLast`, and it equals the stream output).
- seekable-write.AC3.3: `decryptStream(arrayToStream(perRecordCiphertext), key,
  rs)` collected via `streamToArray` equals the original plaintext
  (`t.deepEqual`).
- seekable-write.AC6.1 (completion): extend the Phase 1 export test (or add a
  new assertion) so that, imported from `'../src/ece.js'`,
  `typeof deriveContentSalt === 'function'` and
  `typeof encryptRecord === 'function'`. Add both to the import list at the top
  of `test/seekable-write.ts`.

**Verification:**
Run: `npm test`
Expected: equivalence (incl. exact-multiple), round-trip, and the completed
export-surface test pass.

**Commit:** `test(ece): record/stream equivalence and round-trip`
<!-- END_TASK_3 -->

<!-- END_SUBCOMPONENT_B -->

---

## Phase 2 done when

- `deriveContentSalt` and `encryptRecord` exist, exported from `src/ece.ts`,
  with JSDoc covering the salt-reuse safety model.
- `deriveContentSalt` is deterministic, content-binding, and rejects an empty
  digest.
- `header(salt, rs) || concat(encryptRecord(i, slice_i, isLast))` equals
  `encryptStream(x, key, rs, salt)` byte-for-byte, including the exact-multiple
  final-record case.
- `decryptStream` of the per-record concatenation recovers the plaintext.
- A wrong-sized non-final slice, an over-long final slice, an empty digest, and
  a non-16-byte salt all throw.
- `npm test`, `npm run build`, and `npm run lint` pass.
- Covers seekable-write.AC2.2 (salt half), AC2.3, AC3.2, AC3.3, AC4.4, AC5,
  and completes AC6.1.
