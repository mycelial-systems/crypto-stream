# Seekable Write Implementation Plan — Phase 5

**Goal:** Document the reproducible / record-addressable encryption model and the
new public surface.

**Architecture:** Documentation only. Add a README section explaining the
content-digest safety model and the two-pass (hash then encrypt) flow, document
the new Keychain methods and the low-level `./ece.js` building blocks, and
confirm the JSDoc added in Phases 1-4 is present.

**Tech Stack:** Markdown (README), TSDoc/JSDoc in source.

**Scope:** Phase 5 of 5 (Documentation).

**Codebase verified:** 2026-06-19

**Style rules:** Match the existing README tone and the `## API` /
`### keychain.method(...)` heading structure (`README.md:103-365`). Per the
project's CLAUDE.md, do NOT write tests for docs.

---

## Acceptance Criteria Coverage

**Verifies: None.** This is a documentation phase. It is verified operationally
(docs present, JSDoc present, `npm run lint` passes), not by acceptance-criteria
tests. The feature's ACs are fully covered by Phases 1-4.

---

## Context the engineer needs

- `README.md` has an `## API` section (`README.md:103`) with one `###` heading
  per method, and ends with `## credits` (`README.md:366`). The current
  `encryptStream` entry is `### keychain.encryptStream(stream)`
  (`README.md:226`).

- JSDoc was added inline during Phases 1-4. This phase only verifies it exists
  and is accurate; it does not move code. The public additions that must carry
  JSDoc:
  - `ece.ts`: `recordPlaintextSize`, `recordCount`, `header`,
    `deriveContentSalt`, `encryptRecord`.
  - `keychain.ts`: `contentDigest`, `encryptStream` (updated), `header`,
    `encryptRecord`.

- Safety message to state everywhere it matters: a fixed salt must never encrypt
  two different plaintexts (AES-GCM nonce reuse is catastrophic). That is why the
  salt is derived from the content digest and the Keychain API does not accept a
  raw salt; the `./ece.js` raw-salt functions are low-level building blocks.

- The low-level ece functions are reachable via package.json's existing `"./*"`
  wildcard; no package.json change is needed. IMPORTANT: the build emits to
  `dist/src/ece.js` (the whole package is laid out under `dist/src/`), so the
  working published import path is `@substrate-system/crypto-stream/src/ece`
  (NOT `/ece`, which would resolve to a non-existent `dist/ece.js`). Document
  `@substrate-system/crypto-stream/src/ece` in the README. Do NOT change
  package.json (out of scope).

---

<!-- START_TASK_1 -->
### Task 1: Add the README "Reproducible & record-addressable encryption" section

**Files:**
- Modify: `README.md` (add a new `## Reproducible & record-addressable
  encryption` section; place it after the `## API` method entries and before
  `## credits`, or as a clearly-marked subsection of `## API`)

**Implementation:**
Write a section covering:
1. **The content-digest model.** Reproducible encryption needs a fixed salt, but
   reusing a salt across two different plaintexts breaks AES-GCM. The salt is
   therefore never chosen by the caller: it is derived from the content digest
   (`salt = HKDF(key, info="Content-Encoding: salt\0" || SHA-256(plaintext))`),
   binding each salt to exactly one plaintext. The Keychain API speaks in
   *content digest*, never a raw salt.
2. **The two-pass flow** (hash, then encrypt), with a short code example:
   ```js
   // 1. Hash pass
   const digest = await keychain.contentDigest(file.stream())

   // 2. Encrypt pass — reproducible: same input → identical ciphertext
   const encrypted = await keychain.encryptStream(file.stream(), {
       contentDigest: digest,
       recordSize: rs
   })

   // On demand: regenerate record i byte-identically
   const rec = await keychain.encryptRecord(i, sliceI, {
       isLast,
       contentDigest: digest,
       recordSize: rs
   })
   // Full ciphertext = header(21) || rec0 || rec1 || … || recLast
   const head = await keychain.header({ contentDigest: digest, recordSize: rs })
   ```
   Note that `encryptStream` with no options keeps the original behavior (a fresh
   random salt per call; not reproducible) and is a single pass.
3. **The low-level ece building blocks.** State that
   `@substrate-system/crypto-stream/src/ece` exposes `RECORD_SIZE`,
   `HEADER_LENGTH`, `recordPlaintextSize`, `recordCount`, `header`,
   `deriveContentSalt`, and `encryptRecord` for advanced use, that these take a
   raw salt, and that they are low-level — prefer the Keychain digest API, which
   is footgun-free. (Use the `/src/ece` path, matching how the rest of the
   package is published under `dist/src/`.)

Keep prose tight; reuse the existing README's code-fence style.

**Verification:**
Run: `npm run lint`
Expected: no lint errors (lint covers source; README change must not break any
markdown/lint step that runs). Visually confirm the section renders and the
example matches the implemented signatures.

**Commit:** `docs: reproducible & record-addressable encryption`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Document the new methods in the API reference and verify JSDoc

**Files:**
- Modify: `README.md` (update `### keychain.encryptStream(...)` and add API
  entries for the new methods)
- Verify (no edit unless missing): JSDoc in `src/ece.ts` and `src/keychain.ts`

**Implementation:**
1. Update `### keychain.encryptStream(stream)` (`README.md:226`) to document the
   new optional second argument `{ contentDigest?, recordSize? }`, including that
   passing `contentDigest` makes output reproducible and that omitting options
   preserves the random-salt behavior. Update the signature heading to
   `### keychain.encryptStream(stream[, opts])`.
2. Add `## API` entries (matching the existing `###`/`####` parameter style)
   for:
   - `### keychain.contentDigest(content)` — returns a 32-byte SHA-256; accepts
     ReadableStream / Uint8Array / Blob.
   - `### keychain.header(opts)` — `{ contentDigest, recordSize? }` → 21-byte
     header.
   - `### keychain.encryptRecord(seq, plaintext, opts)` —
     `{ isLast, contentDigest, recordSize? }` → encrypted record.
3. Verify the JSDoc blocks added in Phases 1-4 exist and accurately state the
   salt-reuse safety rule on: `ece.header`, `ece.deriveContentSalt`,
   `ece.encryptRecord`, `keychain.contentDigest`, `keychain.encryptStream`,
   `keychain.header`, `keychain.encryptRecord`. If any is missing or stale, add
   or correct it (the canonical wording is in the Phase 1-4 code blocks).

**Verification:**
Run: `npm run lint`
Expected: no lint errors.
Run: `npm run build`
Expected: `tsc` compiles cleanly (confirms no JSDoc edits broke types).

**Commit:** `docs: API reference for digest-based encrypt surface`
<!-- END_TASK_2 -->

---

## Phase 5 done when

- README has a section documenting the content-digest safety model, the two-pass
  flow, and the low-level `./ece.js` building blocks.
- The API reference documents `encryptStream`'s new options and the new
  `contentDigest` / `header` / `encryptRecord` methods.
- The public additions carry accurate JSDoc stating the salt-reuse safety rule.
- `npm run lint` and `npm run build` pass.
- No tests are added for documentation (per project convention).
