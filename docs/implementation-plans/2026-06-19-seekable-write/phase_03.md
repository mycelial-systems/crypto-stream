# Seekable Write Implementation Plan — Phase 3

**Goal:** Add the content-digest helper to `Keychain` and make
`Keychain.encryptStream` reproducible without ever exposing a raw salt.

**Architecture:** `contentDigest` computes SHA-256 over the plaintext
(ReadableStream / Uint8Array / Blob). `encryptStream` gains an options object;
given a `contentDigest` it derives the salt internally via
`deriveContentSalt(mainKey, digest)` and passes it to `ece.encryptStream`,
producing byte-identical output across calls. With no options it keeps today's
random-salt behavior.

**Tech Stack:** TypeScript (ESM), WebCrypto, tapzero tests.

**Scope:** Phase 3 of 5 (Keychain digest + reproducible stream).

**Codebase verified:** 2026-06-19

**Style rules:** See Phase 1. Match existing `src/keychain.ts`.

---

## Acceptance Criteria Coverage

This phase implements and tests:

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
- **seekable-write.AC2.2 Success (completion):** two different plaintexts yield
  different digests and therefore different `deriveContentSalt` outputs. *(Phase
  2 proved different digests → different salts; this phase proves different
  plaintexts → different digests, completing AC2.2.)*
- **seekable-write.AC2.4 Success:** `contentDigest` accepts `ReadableStream`,
  `Uint8Array`, and `Blob`, producing the same digest for equivalent content.

---

## Context the engineer needs

- `Keychain` stores the raw master key as `this.key:Uint8Array`
  (`src/keychain.ts:17`) and exposes the HKDF `CryptoKey` via
  `this.mainKeyPromise:Promise<CryptoKey>` (`src/keychain.ts:19,27-33`). The HKDF
  CryptoKey is what `ece` functions take as `secretKey`. `this.salt`
  (`src/keychain.ts:18`) is unrelated to ECE content salts — it only feeds the
  metadata key and auth token; leave it untouched.

- Current `encryptStream` method (`src/keychain.ts:157-165`):
  ```ts
  async encryptStream (
      stream:ReadableStream<Uint8Array>
  ):Promise<ReadableStream<Uint8Array>> {
      if (!(stream instanceof ReadableStream)) {
          throw new TypeError('This is not a readable stream')
      }
      const mainKey = await this.mainKeyPromise
      return encryptStream(stream, mainKey)
  }
  ```
  The current call uses `ece.encryptStream`'s defaults: `rs = RECORD_SIZE` and a
  fresh random salt. Backward compatibility (AC1.2) requires preserving that
  exact behavior when no options are passed.

- `ece.encryptStream` signature (`src/ece.ts:366-381`):
  `encryptStream(input, secretKey, rs = RECORD_SIZE, salt = generateSalt(KEY_LENGTH))`.
  To pass a derived `salt` you must also pass `rs` (positional). Import
  `RECORD_SIZE` (exported in Phase 1) and `deriveContentSalt` (added in Phase 2)
  from `./ece.js`.

- Keychain's current ece imports (`src/keychain.ts:3-8`):
  ```ts
  import {
      decryptStream,
      decryptStreamRange,
      encryptStream,
      KEY_LENGTH,
  } from './ece.js'
  ```
  Extend this list with `RECORD_SIZE` and `deriveContentSalt`.

- `asBufferSource` is already imported (`src/keychain.ts:9`) and is used to pass
  `Uint8Array` to WebCrypto. `webcrypto` is imported (`src/keychain.ts:1`).

- WebCrypto has no incremental/streaming SHA-256, and the design forbids new
  dependencies. So `contentDigest` collects stream/Blob bytes into one buffer,
  then one-shot `subtle.digest('SHA-256', …)`. The design's "where the platform
  allows" clause covers this — buffering is the correct call here. `Response` is
  available in Node 18+ and browsers (the existing `test/stream.ts` already uses
  `new Response(stream)`), so reuse that pattern to drain a stream.

- `decryptStream` method (`src/keychain.ts:246-254`) is unchanged; the AC1.2
  round-trip test uses it.

---

<!-- START_SUBCOMPONENT_C (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: Add Keychain.contentDigest

**Verifies:** seekable-write.AC2.1, seekable-write.AC2.2 (digest half),
seekable-write.AC2.4

**Files:**
- Modify: `src/keychain.ts` (add a method on the `Keychain` class, e.g. directly
  above `encryptStream` at `src/keychain.ts:157`)
- Test: `test/seekable-write.ts`

**Implementation:**
SHA-256 over the plaintext, accepting `ReadableStream<Uint8Array>`,
`Uint8Array`, or `Blob`, returning 32 bytes.

```ts
    /**
     * SHA-256 digest of the plaintext, used as the input to content-bound salt
     * derivation. Accepts a stream, a byte array, or a Blob; equivalent content
     * yields the same digest.
     *
     * Pass the result to `encryptStream`/`header`/`encryptRecord` as
     * `contentDigest`. The salt is derived from this digest internally, so the
     * Keychain API never exposes a raw salt — a fixed salt can never pair with
     * two different plaintexts.
     *
     * NOTE: WebCrypto has no incremental hash, so a stream/Blob is drained into
     * memory before hashing.
     *
     * @param content Plaintext as a ReadableStream, Uint8Array, or Blob.
     * @returns 32-byte SHA-256 digest.
     */
    async contentDigest (
        content:ReadableStream<Uint8Array>|Uint8Array|Blob
    ):Promise<Uint8Array<ArrayBuffer>> {
        let bytes:Uint8Array
        if (content instanceof Uint8Array) {
            bytes = content
        } else if (content instanceof ReadableStream) {
            bytes = new Uint8Array(await new Response(content).arrayBuffer())
        } else if (typeof Blob !== 'undefined' && content instanceof Blob) {
            bytes = new Uint8Array(await content.arrayBuffer())
        } else {
            throw new TypeError(
                'content must be a ReadableStream, Uint8Array, or Blob'
            )
        }

        const digest = await webcrypto.subtle.digest(
            'SHA-256',
            asBufferSource(bytes)
        )
        return new Uint8Array(digest)
    }
```

**Testing:**
In `test/seekable-write.ts`:
- seekable-write.AC2.1: `contentDigest(bytes)` returns a 32-byte array
  (`t.equal(d.byteLength, 32)`), and two calls on the same input are equal
  (`t.deepEqual`).
- seekable-write.AC2.4: for the same underlying bytes, the digests from a
  `Uint8Array`, `arrayToStream(bytes)`, and `new Blob([bytes])` are all equal
  (`t.deepEqual`). Construct the keychain with `new Keychain()`.
- seekable-write.AC2.2 (digest half + end to end): two DIFFERENT plaintexts give
  different digests (assert NOT equal), and feeding those digests through
  `deriveContentSalt(mainKey, digest)` (import from `'../src/ece.js'`;
  `mainKey = await keychain['mainKeyPromise']` or via a fresh `makeKey`) yields
  different salts. This closes AC2.2 together with Phase 2.

**Verification:**
Run: `npm test`
Expected: digest stability, multi-input equality, and content-binding pass.

**Commit:** `feat(keychain): add contentDigest (SHA-256 over plaintext)`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Make encryptStream reproducible via options

**Verifies:** seekable-write.AC1.1, seekable-write.AC1.2, seekable-write.AC1.3,
seekable-write.AC1.4

**Files:**
- Modify: `src/keychain.ts:3-8` (extend ece imports)
- Modify: `src/keychain.ts:157-165` (change `encryptStream` signature/body)
- Test: `test/seekable-write.ts`

**Implementation:**
Extend the ece import list:

```ts
import {
    decryptStream,
    decryptStreamRange,
    encryptStream,
    deriveContentSalt,
    KEY_LENGTH,
    RECORD_SIZE,
} from './ece.js'
```

Add an options type and change `encryptStream` to accept it. When
`contentDigest` is present, derive the salt and pass it (with `rs`) to
`ece.encryptStream`; otherwise call exactly as before so the random-salt path is
unchanged.

```ts
    /**
     * Take a stream, return an encrypted stream.
     *
     * With `opts.contentDigest`, the ECE salt is derived from the digest
     * internally (`deriveContentSalt`), so two calls over identical input
     * produce byte-identical ciphertext (reproducible encryption). With no
     * opts, a fresh random salt is used (today's behavior).
     *
     * The salt is never accepted directly: because it is bound to the content
     * digest, a fixed salt can never encrypt two different plaintexts (AES-GCM
     * nonce-reuse is structurally unreachable from this API).
     *
     * @param stream Input plaintext stream.
     * @param opts Optional `{ contentDigest?, recordSize? }`.
     * @returns Encrypted stream.
     */
    async encryptStream (
        stream:ReadableStream<Uint8Array>,
        opts:{
            contentDigest?:Uint8Array,
            recordSize?:number
        } = {}
    ):Promise<ReadableStream<Uint8Array>> {
        if (!(stream instanceof ReadableStream)) {
            throw new TypeError('This is not a readable stream')
        }
        const mainKey = await this.mainKeyPromise
        const rs = opts.recordSize ?? RECORD_SIZE

        if (opts.contentDigest) {
            const salt = await deriveContentSalt(mainKey, opts.contentDigest)
            return encryptStream(stream, mainKey, rs, salt)
        }

        return encryptStream(stream, mainKey, rs)
    }
```

When `recordSize` is omitted, `rs` is `RECORD_SIZE` — identical to the previous
default. When neither option is set, the no-digest branch calls
`encryptStream(stream, mainKey, RECORD_SIZE)`, which uses `ece.encryptStream`'s
random-salt default; behavior matches the prior `encryptStream(stream, mainKey)`.

**Testing:**
In `test/seekable-write.ts` (use the `arrayToStream`/`streamToArray` helpers;
import `encryptedSize` from `'../src/index.js'` or `'../src/ece.js'`):
- seekable-write.AC1.1: with `digest = await keychain.contentDigest(data)`,
  collect `encryptStream(arrayToStream(data), { contentDigest: digest })` twice
  and assert the two outputs are `deepEqual`.
- seekable-write.AC1.2: `encryptStream(arrayToStream(data))` (no opts) twice
  produces DIFFERENT outputs (random salt; assert NOT equal). Then each output
  round-trips: `decryptStream` → `streamToArray` equals `data`.
- seekable-write.AC1.3: `encryptStream(arrayToStream(data), { recordSize: rs })`
  output length equals `encryptedSize(data.length, rs)` for a small `rs` that
  forces multiple records. (A fresh random salt is fine; only length matters.)
- seekable-write.AC1.4: `encryptStream(arrayToStream(new Uint8Array(0)),
  { contentDigest: await keychain.contentDigest(new Uint8Array(0)) })` collected
  has length exactly `HEADER_LENGTH` (21). (Also valid with no opts.)

Use one `new Keychain()` per test. For AC1.1, the SAME keychain instance must be
used for both encrypts (the salt depends on the main key).

**Verification:**
Run: `npm test`
Expected: reproducibility, backward-compat round-trip, record-size sizing, and
empty-input tests pass.

**Commit:** `feat(keychain): reproducible encryptStream via contentDigest opts`
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_C -->

---

## Phase 3 done when

- `Keychain.contentDigest` exists, returns a stable 32-byte SHA-256 for
  stream / Uint8Array / Blob, and equivalent content hashes equally.
- `Keychain.encryptStream(stream, opts?)` is byte-identical across calls when
  given a `contentDigest`, honors `recordSize`, and — with no opts — still uses a
  random salt and round-trips.
- The Keychain API still exposes no raw salt.
- `npm test`, `npm run build`, and `npm run lint` pass.
- Covers seekable-write.AC1 and completes seekable-write.AC2.
