# Seekable Write — Test Requirements

## Summary

This feature has 22 acceptance criteria (AC1.1 through AC6.2). All 22 are
automated. Every AC is a deterministic crypto or geometry property, so each maps
to a tapzero test in `test/seekable-write.ts` (registered from `test/index.ts`).
Run the whole suite with `npm test`. There is no UI and nothing that requires
human verification.

## Automated Tests

All tests live in `test/seekable-write.ts` and are unit-level — they exercise
individual functions and methods directly (geometry, header bytes, salt
derivation, single-record encrypt, and the Keychain digest API), with a few
that compose per-record output and compare it to the streaming encoder.

| AC id | AC text | Phase / Task | Type | Test file | Asserts |
|---|---|---|---|---|---|
| seekable-write.AC1.1 | `encryptStream(x, { contentDigest })` called twice over identical input produces byte-identical ciphertext. | Phase 3 / Task 2 | unit | test/seekable-write.ts | Two encrypts of the same data with the same digest on the same Keychain are byte-for-byte equal (`t.deepEqual`). |
| seekable-write.AC1.2 | `encryptStream(x)` with no opts produces a different ciphertext on two calls (fresh random salt) and each round-trips via `decryptStream`. | Phase 3 / Task 2 | unit | test/seekable-write.ts | Two no-opts encrypts differ, and each decrypts back to the original plaintext. |
| seekable-write.AC1.3 | `encryptStream(x, { recordSize: rs })` places record boundaries at `rs` (output length equals `encryptedSize(len, rs)`). | Phase 3 / Task 2 | unit | test/seekable-write.ts | Ciphertext length equals `encryptedSize(len, rs)` for an `rs` forcing multiple records. |
| seekable-write.AC1.4 | `encryptStream` of empty input emits only the 21-byte header. | Phase 3 / Task 2 | unit | test/seekable-write.ts | Encrypting empty input yields output of length exactly `HEADER_LENGTH` (21). |
| seekable-write.AC2.1 | `contentDigest(x)` returns a stable 32-byte value (same input yields the same digest). | Phase 3 / Task 1 | unit | test/seekable-write.ts | `contentDigest` returns 32 bytes and two calls on the same input are equal. |
| seekable-write.AC2.2 | two different plaintexts yield different digests and therefore different `deriveContentSalt` outputs. | Phase 2 / Task 1 (salt half) + Phase 3 / Task 1 (digest half, completes) | unit | test/seekable-write.ts | Different digests derive different salts (Phase 2); different plaintexts produce different digests that derive different salts end to end (Phase 3 completes). |
| seekable-write.AC2.3 | `deriveContentSalt(key, digest)` is deterministic for the same `(key, digest)`. | Phase 2 / Task 1 | unit | test/seekable-write.ts | Two derivations from the same key and digest return equal 16-byte salts. |
| seekable-write.AC2.4 | `contentDigest` accepts `ReadableStream`, `Uint8Array`, and `Blob`, producing the same digest for equivalent content. | Phase 3 / Task 1 | unit | test/seekable-write.ts | Digests of the same bytes via Uint8Array, stream, and Blob are all equal. |
| seekable-write.AC3.1 | `header(salt, rs)` equals the first 21 bytes of `encryptStream` output for the same salt and rs. | Phase 1 / Task 3 | unit | test/seekable-write.ts | `header(salt, rs)` equals the first `HEADER_LENGTH` bytes of stream output for the same salt and rs. |
| seekable-write.AC3.2 | `header(salt, rs) \|\| concat(encryptRecord(i, slice_i, isLast))` equals a full `encryptStream(x, rs, salt)`, byte for byte. | Phase 2 / Task 3 | unit | test/seekable-write.ts | Per-record reconstruction equals the full stream output byte-for-byte across several plaintext lengths. |
| seekable-write.AC3.3 | `decryptStream` of that per-record concatenation recovers the original plaintext. | Phase 2 / Task 3 (low-level) + Phase 4 / Task 3 (via Keychain) | unit | test/seekable-write.ts | Decrypting the per-record concatenation returns the original plaintext. |
| seekable-write.AC3.4 | the same round-trip holds through the Keychain digest API (`keychain.header(...)` + `keychain.encryptRecord(...)`). | Phase 4 / Task 3 | unit | test/seekable-write.ts | A ciphertext built entirely via `keychain.header` + `keychain.encryptRecord` decrypts back to the plaintext (single- and multi-record). |
| seekable-write.AC4.1 | `recordPlaintextSize(rs)` equals `rs - 17` (and for the default record size). | Phase 1 / Task 2 | unit | test/seekable-write.ts | `recordPlaintextSize()` equals `RECORD_SIZE - 17` and `recordPlaintextSize(1024)` equals 1007. |
| seekable-write.AC4.2 | `recordCount(n, rs)` equals `ceil(n / (rs - 17))` for `n > 0`. | Phase 1 / Task 2 | unit | test/seekable-write.ts | `recordCount(n, rs)` matches `ceil(n / (rs - 17))` for boundary cases (1, exactly one record, one over). |
| seekable-write.AC4.3 | `recordCount(0) === 0`. | Phase 1 / Task 2 (function) + Phase 4 / Task 3 (end to end) | unit | test/seekable-write.ts | `recordCount(0)` is 0; end to end an empty plaintext yields header-only output that decrypts to empty. |
| seekable-write.AC4.4 | a plaintext of length exactly `k*(rs - 17)` produces `k` records with a valid full final record. | Phase 1 / Task 2 (count) + Phase 2 / Task 3 (final record, completes) | unit | test/seekable-write.ts | `recordCount(k*(rs-17))` is `k` (Phase 1); an exact-multiple input reconstructs byte-for-byte with a valid full final record (Phase 2 completes). |
| seekable-write.AC5.1 | `encryptRecord` with a non-final slice whose length differs from `recordPlaintextSize(rs)` throws. | Phase 2 / Task 2 | unit | test/seekable-write.ts | A non-final slice of the wrong length rejects. |
| seekable-write.AC5.2 | `encryptRecord` with a final slice longer than `recordPlaintextSize(rs)` throws. | Phase 2 / Task 2 | unit | test/seekable-write.ts | A final slice longer than the max rejects. |
| seekable-write.AC5.3 | `deriveContentSalt` with an empty digest throws. | Phase 2 / Task 1 | unit | test/seekable-write.ts | `deriveContentSalt(key, empty)` rejects. |
| seekable-write.AC5.4 | a non-16-byte salt passed to a low-level `ece` function throws `Invalid salt length`. | Phase 2 / Task 2 | unit | test/seekable-write.ts | A 15-byte salt rejects with a message matching `/Invalid salt length/`. |
| seekable-write.AC6.1 | `RECORD_SIZE`, `HEADER_LENGTH`, `recordPlaintextSize`, `recordCount`, `header`, `deriveContentSalt`, and `encryptRecord` are importable from the `./ece.js` subpath. | Phase 1 / Task 4 (five names) + Phase 2 / Task 3 (completes) | unit | test/seekable-write.ts | The five Phase-1 names are importable (Phase 1); `deriveContentSalt` and `encryptRecord` are also importable (Phase 2 completes). |
| seekable-write.AC6.2 | the root `index.ts` export surface gains none of these names (the curated root export is unchanged). | Phase 1 / Task 4 | unit | test/seekable-write.ts | None of the seven new names appear on the root `index.ts` export surface. |

Notes on ACs split across phases (the final listed phase completes the AC):

- AC2.2 — Phase 2 proves different digests derive different salts; Phase 3
  proves different plaintexts produce different digests, closing it end to end.
- AC3.3 — Phase 2 proves it for the low-level per-record build; Phase 4 also
  proves it through the Keychain surface.
- AC4.3 — Phase 1 proves `recordCount(0) === 0` as a function; Phase 4 proves
  the empty-input round-trip end to end.
- AC4.4 — Phase 1 proves the record count for an exact multiple; Phase 2
  completes it by showing the full final record is valid via stream equivalence.
- AC6.1 — Phase 1 covers the five names available after Phase 1; Phase 2
  extends the import test to `deriveContentSalt` and `encryptRecord`.

The byte-for-byte equality checks use `t.deepEqual` on the Uint8Arrays. AC1.3
checks output length against `encryptedSize(len, rs)`. AC5.4 asserts the
`Invalid salt length` message via a RegExp matcher. The reproducibility check
(AC1.1) uses the same `Keychain` instance across both encrypts, since the
derived salt depends on the main key.

## Human Verification

None — every acceptance criterion is covered by an automated test. This is a
library-only change consisting of deterministic crypto and geometry functions;
there is no UI and nothing that needs a human to look at.

Optional, non-blocking smoke check (not required for any AC): a consumer can
import the low-level building blocks from
`@substrate-system/crypto-stream/src/ece` (`RECORD_SIZE`, `HEADER_LENGTH`,
`recordPlaintextSize`, `recordCount`, `header`, `deriveContentSalt`,
`encryptRecord`) in a downstream project and confirm the published subpath
resolves. The in-repo AC6.1 test already verifies these imports against the
source module, so this is just a published-package sanity check.

## Coverage Checklist

All 22 acceptance criteria appear in the Automated Tests section:

- [x] seekable-write.AC1.1
- [x] seekable-write.AC1.2
- [x] seekable-write.AC1.3
- [x] seekable-write.AC1.4
- [x] seekable-write.AC2.1
- [x] seekable-write.AC2.2
- [x] seekable-write.AC2.3
- [x] seekable-write.AC2.4
- [x] seekable-write.AC3.1
- [x] seekable-write.AC3.2
- [x] seekable-write.AC3.3
- [x] seekable-write.AC3.4
- [x] seekable-write.AC4.1
- [x] seekable-write.AC4.2
- [x] seekable-write.AC4.3
- [x] seekable-write.AC4.4
- [x] seekable-write.AC5.1
- [x] seekable-write.AC5.2
- [x] seekable-write.AC5.3
- [x] seekable-write.AC5.4
- [x] seekable-write.AC6.1
- [x] seekable-write.AC6.2
