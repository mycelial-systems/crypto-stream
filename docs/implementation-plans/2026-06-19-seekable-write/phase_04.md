# Seekable Write Implementation Plan — Phase 4

**Goal:** Expose the safe, digest-based record surface on `Keychain` and prove
the per-record concatenation round-trips through `decryptStream`.

**Architecture:** `Keychain.header({ contentDigest, recordSize? })` and
`Keychain.encryptRecord(seq, plaintext, { isLast, contentDigest, recordSize? })`
derive the salt internally via `deriveContentSalt(mainKey, digest)` and delegate
to the low-level `ece.header` / `ece.encryptRecord`. The full ciphertext is
`keychain.header(...) || rec0 || … || recLast`, which `decryptStream` decrypts
back to the original plaintext.

**Tech Stack:** TypeScript (ESM), WebCrypto, tapzero tests.

**Scope:** Phase 4 of 5 (Keychain record methods).

**Codebase verified:** 2026-06-19

**Style rules:** See Phase 1. Match existing `src/keychain.ts`.

---

## Acceptance Criteria Coverage

This phase implements and tests:

### seekable-write.AC3: Record/stream equivalence
- **seekable-write.AC3.3 Success (via Keychain):** `decryptStream` of the
  per-record concatenation recovers the original plaintext.
- **seekable-write.AC3.4 Success:** the same round-trip holds through the
  Keychain digest API (`keychain.header(...)` + `keychain.encryptRecord(...)`).

### seekable-write.AC4: Record geometry and edges
- **seekable-write.AC4.3 Edge (end to end):** `recordCount(0) === 0` holds end
  to end — an empty plaintext yields header-only output that still round-trips.

---

## Context the engineer needs

- `this.mainKeyPromise:Promise<CryptoKey>` (`src/keychain.ts:19`) is the HKDF
  CryptoKey passed to ece functions. `Keychain.contentDigest` exists from
  Phase 3; `ece.header`, `ece.encryptRecord`, and `ece.deriveContentSalt` exist
  from Phases 1-2.

- Extend the ece import list (`src/keychain.ts:3-8`, already extended in Phase 3
  with `deriveContentSalt`, `RECORD_SIZE`) to also bring in `header` and
  `encryptRecord`. Both must be imported under DIFFERENT local names from the
  Keychain methods to avoid shadowing — alias them, e.g.:
  ```ts
  import {
      decryptStream,
      decryptStreamRange,
      encryptStream,
      deriveContentSalt,
      header as eceHeader,
      encryptRecord as eceEncryptRecord,
      KEY_LENGTH,
      RECORD_SIZE,
  } from './ece.js'
  ```
  (The class methods are `this.header` / `this.encryptRecord`, so there is no
  hard collision, but aliasing the imports keeps the bodies unambiguous and
  avoids accidental recursion.)

- `ece.header(salt, rs)` returns 21 bytes (Phase 1). `ece.encryptRecord(secretKey,
  seq, plaintext, isLast, salt, rs)` returns the encrypted record (Phase 2) and
  enforces the slice-length rules.

- `decryptStream` reads the salt from the header, so it is agnostic to how the
  salt was derived — a per-record concatenation built with a derived salt
  decrypts normally.

- For the empty-input case: `recordCount(0) === 0`, so there are no records;
  the ciphertext is just `keychain.header(...)` (21 bytes) and `decryptStream`
  returns empty plaintext.

---

<!-- START_SUBCOMPONENT_D (tasks 1-3) -->

<!-- START_TASK_1 -->
### Task 1: Add Keychain.header

**Verifies:** (supports seekable-write.AC3.4)

**Files:**
- Modify: `src/keychain.ts:3-8` (add `header as eceHeader` to the import list)
- Modify: `src/keychain.ts` (add method near `encryptStream`)
- Test: covered by Task 3's round-trip.

**Implementation:**
Async method that derives the salt from the digest and builds the canonical
header. Speaks in content digest only — no raw salt.

```ts
    /**
     * Build the 21-byte ECE header for content identified by `contentDigest`.
     * The salt is derived internally from the digest, so this never exposes a
     * raw salt. The header is byte-identical to the header that
     * `encryptStream({ contentDigest, recordSize })` emits for the same input.
     *
     * @param opts `{ contentDigest, recordSize? }`.
     * @returns The 21-byte header.
     */
    async header (
        opts:{ contentDigest:Uint8Array, recordSize?:number }
    ):Promise<Uint8Array<ArrayBuffer>> {
        const mainKey = await this.mainKeyPromise
        const salt = await deriveContentSalt(mainKey, opts.contentDigest)
        return eceHeader(salt, opts.recordSize ?? RECORD_SIZE)
    }
```

**Verification:**
Run: `npm test`
Expected: compiles and is exercised by Task 3.

**Commit:** `feat(keychain): add digest-based header()`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Add Keychain.encryptRecord

**Verifies:** (supports seekable-write.AC3.4)

**Files:**
- Modify: `src/keychain.ts:3-8` (add `encryptRecord as eceEncryptRecord`)
- Modify: `src/keychain.ts` (add method near `header`)
- Test: covered by Task 3's round-trip.

**Implementation:**
Async method that derives the salt and delegates to `ece.encryptRecord`. The
options object carries `isLast`, `contentDigest`, and optional `recordSize`.

```ts
    /**
     * Encrypt a single ECE record by index, byte-identical to record `seq` of
     * `encryptStream({ contentDigest, recordSize })`. The salt is derived from
     * `contentDigest` internally; no raw salt is accepted.
     *
     * Non-final records must be exactly `recordPlaintextSize(recordSize)`
     * bytes; the final record must be `<=` that. The low-level function throws
     * otherwise.
     *
     * @param seq Zero-based record index.
     * @param plaintext The record's plaintext slice.
     * @param opts `{ isLast, contentDigest, recordSize? }`.
     * @returns The encrypted record bytes.
     */
    async encryptRecord (
        seq:number,
        plaintext:Uint8Array,
        opts:{
            isLast:boolean,
            contentDigest:Uint8Array,
            recordSize?:number
        }
    ):Promise<Uint8Array> {
        const mainKey = await this.mainKeyPromise
        const salt = await deriveContentSalt(mainKey, opts.contentDigest)
        return eceEncryptRecord(
            mainKey,
            seq,
            plaintext,
            opts.isLast,
            salt,
            opts.recordSize ?? RECORD_SIZE
        )
    }
```

**Verification:**
Run: `npm test`
Expected: compiles and is exercised by Task 3.

**Commit:** `feat(keychain): add digest-based encryptRecord()`
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Keychain round-trip and empty-input tests

**Verifies:** seekable-write.AC3.3 (via Keychain), seekable-write.AC3.4,
seekable-write.AC4.3 (end to end)

**Files:**
- Modify: `test/seekable-write.ts`

**Implementation (test-only):**
Use `recordPlaintextSize`, `recordCount` (from `'../src/ece.js'`), and the
`arrayToStream`/`streamToArray` helpers. Build the full ciphertext entirely
through the Keychain digest API, then decrypt it.

Procedure for a given `data` and small `rs`:
1. `const keychain = new Keychain()`
2. `const digest = await keychain.contentDigest(data)`
3. `const head = await keychain.header({ contentDigest: digest, recordSize: rs })`
4. `const max = recordPlaintextSize(rs)`,
   `const n = recordCount(data.length, rs)`
5. For `i` in `0 … n - 1`: `const slice = data.subarray(i*max, (i+1)*max)`;
   `await keychain.encryptRecord(i, slice, { isLast: i === n - 1, contentDigest:
   digest, recordSize: rs })`
6. Concatenate `head || rec0 || … || recLast` into one `Uint8Array`.
7. `const plain = await streamToArray(await keychain.decryptStream(
   arrayToStream(cipher), rs))`

Decryption note: `keychain.decryptStream` (`src/keychain.ts:246-254`) takes only
the stream and decrypts at the default record size. So choose the decrypt path
by record size:

- **Default `rs` (single-record case):** omit `recordSize` everywhere (header,
  every `encryptRecord`, decrypt). Decrypt with `keychain.decryptStream(stream)`
  so the round-trip stays purely on the Keychain surface (AC3.4). A short `data`
  (a few bytes) is a single record at the default `rs` and is sufficient here.
- **Small `rs` (multi-record case):** build header/records with that `rs`, then
  decrypt with the module-level `ece.decryptStream(stream, mainKey, rs)` (import
  `decryptStream` from `'../src/ece.js'`; `mainKey = await
  keychain['mainKeyPromise']`), since `keychain.decryptStream` does not take a
  record size.

**Testing:**
- seekable-write.AC3.4: for a non-empty `data`, the reconstructed plaintext
  equals `data` (`t.deepEqual`). Cover both a single-record case (default `rs`,
  via `keychain.decryptStream`) and a multi-record case (small `rs`, via
  `ece.decryptStream(stream, mainKey, rs)` where `mainKey = await
  keychain['mainKeyPromise']`).
- seekable-write.AC3.3 (via Keychain): this is the same reconstruction →
  `decryptStream` recovers the plaintext; the multi-record assertion above
  satisfies it.
- seekable-write.AC4.3 (end to end): for `data = new Uint8Array(0)`,
  `recordCount(0, rs) === 0` so no records are produced; the ciphertext is just
  the 21-byte header; decrypting it yields an empty `Uint8Array`
  (`t.equal(plain.length, 0)`).

**Verification:**
Run: `npm test`
Expected: single- and multi-record round-trips and the empty-input case pass.

**Commit:** `test(keychain): digest-API round-trip and empty input`
<!-- END_TASK_3 -->

<!-- END_SUBCOMPONENT_D -->

---

## Phase 4 done when

- `Keychain.header` and `Keychain.encryptRecord` exist, speak in content digest
  (no raw salt), and delegate to the aliased `ece` functions.
- `decryptStream` of `keychain.header(...) || concat(keychain.encryptRecord(i,
  slice_i, …))` recovers the original plaintext (single- and multi-record).
- An empty plaintext yields header-only output and `recordCount(0) === 0` holds
  end to end.
- `npm test`, `npm run build`, and `npm run lint` pass.
- Covers seekable-write.AC3.3 (via Keychain), AC3.4, and AC4.3 (end to end).
