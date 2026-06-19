# Seekable Write Implementation Plan — Phase 1

**Goal:** Expose ECE record geometry and a single canonical 21-byte header
builder shared with the streaming encoder.

**Architecture:** Promote two module-private constants to exports, add two pure
geometry helpers next to the existing `encryptedSize`/`plaintextSize` helpers,
and add a `header(salt, rs)` function that the existing
`ECETransformer.createHeader` delegates to so the standalone header is
byte-identical to the stream's header.

**Tech Stack:** TypeScript (ESM, `"type": "module"`), `@substrate-system/tapzero`
tests, esbuild test runner, `tsc` build.

**Scope:** Phase 1 of 5 (Record geometry and canonical header).

**Codebase verified:** 2026-06-19

---

## Style rules (apply to every code edit in this plan)

The existing `src/ece.ts` / `src/keychain.ts` and the project's CLAUDE.md set the
house style. These OVERRIDE generic TypeScript-skill defaults:

- No space between identifier and type annotation: `salt:Uint8Array<ArrayBuffer>`.
- Lines wrap at 80 columns.
- Top-level functions use `function` declarations and named exports.
- Throw `Error`/`TypeError` for invalid input (this is a low-level crypto module;
  it does NOT use neverthrow/Result types).
- Ternary style (when needed):
  ```ts
  const x = cond ?
      a :
      b
  ```
- 4-space indentation, no semicolon-free style change (match existing file).

---

## Acceptance Criteria Coverage

This phase implements and tests:

### seekable-write.AC3: Record/stream equivalence
- **seekable-write.AC3.1 Success:** `header(salt, rs)` equals the first 21
  bytes of `encryptStream` output for the same salt and rs.

### seekable-write.AC4: Record geometry and edges
- **seekable-write.AC4.1 Success:** `recordPlaintextSize(rs)` equals `rs - 17`
  (and for the default record size).
- **seekable-write.AC4.2 Success:** `recordCount(n, rs)` equals
  `ceil(n / (rs - 17))` for `n > 0`.
- **seekable-write.AC4.3 Edge:** `recordCount(0) === 0`.
- **seekable-write.AC4.4 Edge:** a plaintext of length exactly `k*(rs - 17)`
  produces `k` records with a valid full final record. *(This phase covers the
  count: `recordCount(k*(rs-17)) === k`. The "valid full final record" half is
  completed in Phase 2 via record/stream equivalence.)*

### seekable-write.AC6: Export surface (cross-cutting)
- **seekable-write.AC6.1 Success:** `RECORD_SIZE`, `HEADER_LENGTH`,
  `recordPlaintextSize`, `recordCount`, `header`, `deriveContentSalt`, and
  `encryptRecord` are importable from the `./ece.js` subpath. *(This phase tests
  the five names available after Phase 1: `RECORD_SIZE`, `HEADER_LENGTH`,
  `recordPlaintextSize`, `recordCount`, `header`. `deriveContentSalt` and
  `encryptRecord` are added and tested in Phase 2.)*
- **seekable-write.AC6.2 Success:** the root `index.ts` export surface gains
  none of these names (the curated root export is unchanged).

---

## Context the engineer needs

- `src/ece.ts:15-19` currently has:
  ```ts
  export const KEY_LENGTH = 16
  export const TAG_LENGTH = 16
  const NONCE_LENGTH = 12
  const RECORD_SIZE = 64 * 1024
  const HEADER_LENGTH = KEY_LENGTH + 4 + 1 // salt + record size + idlen
  ```
  `KEY_LENGTH` and `TAG_LENGTH` are already exported. `RECORD_SIZE` and
  `HEADER_LENGTH` are NOT — this phase exports them.

- `src/ece.ts:154-161` is the current header builder inside `ECETransformer`:
  ```ts
  createHeader ():Uint8Array {
      if (!this.salt) throw new Error('Not salt')
      const header = new Uint8Array(HEADER_LENGTH)
      header.set(this.salt)
      const dv = new DataView(header.buffer, header.byteOffset, header.byteLength)
      dv.setUint32(KEY_LENGTH, this.rs)
      return header
  }
  ```
  Note `dv.setUint32` is big-endian by default. The new `header()` must produce
  the identical 21 bytes.

- `src/ece.ts:313-356` contains the existing `encryptedSize`/`plaintextSize`
  helpers. They guard inputs with `if (!Number.isInteger(x)) throw new
  TypeError('x')`. The new geometry helpers mirror this exact style. Add the new
  functions immediately after `plaintextSize` (after `src/ece.ts:356`).

- `src/ece.ts:366-381` is the module-level `encryptStream`:
  ```ts
  export function encryptStream (
      input:ReadableStream,
      secretKey:CryptoKey,
      rs:number = RECORD_SIZE,
      salt:Uint8Array<ArrayBuffer> = generateSalt(KEY_LENGTH)
  ):ReadableStream { ... }
  ```
  It accepts an explicit `salt`, which the AC3.1 test uses to force a fixed salt.

- `src/index.ts` is the curated root surface; do NOT modify it:
  ```ts
  export { Keychain, plaintextSize, encryptedSize } from './keychain.js'
  export { transformStream } from './transform-stream.js'
  ```

- Subpath export: `package.json` has no explicit `./ece` entry. The build
  (`tsc --project tsconfig.build.json`, which extends `tsconfig.json` with
  `rootDir:"."`, `outDir:"dist"`) emits to `dist/src/ece.js` — NOT `dist/ece.js`
  (the whole package is already laid out under `dist/src/`; even `main` is
  `dist/index.js` while the real file is `dist/src/index.js`). The existing
  `"./*"` wildcard therefore makes the working published subpath
  `@substrate-system/crypto-stream/src/ece` (resolving to `dist/src/ece.js`),
  NOT `/ece`. So AC6.1's subpath works WITHOUT a package.json change (consistent
  with the design's "two files change"), but the consumer path is `/src/ece`.
  Do NOT modify `package.json` — fixing only `/ece` while `main` stays off-by-
  `src/` would be inconsistent and is out of scope. In tests, import the
  functions from the source module `'../src/ece.js'` (this is what verifies
  AC6.1 in-repo; dist is not built during `npm test`).

- Testing: tapzero. New test file is `test/seekable-write.ts`, registered by
  adding `import './seekable-write.js'` to `test/index.ts`. Run with `npm test`.
  Assertions: `t.equal` (strict), `t.deepEqual` (byte-for-byte Uint8Array
  compare), `t.ok`, `t.throws` (async-aware: it awaits the function and accepts
  a `RegExp` matcher, so it works for rejected promises too). Build with
  `npm run build`; lint with
  `npm run lint`.

---

<!-- START_SUBCOMPONENT_A (tasks 1-4) -->

<!-- START_TASK_1 -->
### Task 1: Promote RECORD_SIZE and HEADER_LENGTH to exports

**Files:**
- Modify: `src/ece.ts:18-19`

**Implementation:**
Change the two module-private `const` declarations to `export const`. Values and
the trailing comment stay identical:

```ts
export const RECORD_SIZE = 64 * 1024
export const HEADER_LENGTH = KEY_LENGTH + 4 + 1 // salt + record size + idlen
```

Leave `NONCE_LENGTH` (line 17), `MODE_ENCRYPT`/`MODE_DECRYPT` (lines 13-14)
module-private — they are not part of this feature's surface.

**Verification:**
Run: `npm run build`
Expected: `tsc` compiles with no errors.

**Commit:** `feat(ece): export RECORD_SIZE and HEADER_LENGTH`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Add recordPlaintextSize and recordCount geometry helpers

**Verifies:** seekable-write.AC4.1, seekable-write.AC4.2, seekable-write.AC4.3,
seekable-write.AC4.4 (count)

**Files:**
- Modify: `src/ece.ts` (add after `plaintextSize`, i.e. after `src/ece.ts:356`)
- Test: `test/seekable-write.ts` (created in Task 4)

**Implementation:**
Add two pure functions. `recordPlaintextSize` returns the plaintext bytes that
fit in one record (`rs - TAG_LENGTH - 1`, i.e. `rs - 17`, accounting for the
16-byte AES-GCM tag and the 1-byte padding delimiter). `recordCount` returns
`ceil(plaintextSize / recordPlaintextSize(rs))`, which is `0` for empty input
(do NOT special-case with `Math.max(1, …)`). Both mirror the `Number.isInteger`
guard style of `encryptedSize`/`plaintextSize`.

```ts
/**
 * Plaintext bytes that fit in one ECE record for the given record size.
 * Equals `rs - TAG_LENGTH - 1` (the 16-byte AES-GCM tag plus the 1-byte
 * padding delimiter).
 *
 * @param rs Record size in bytes (default RECORD_SIZE).
 * @returns Plaintext bytes per record.
 */
export function recordPlaintextSize (rs:number = RECORD_SIZE):number {
    if (!Number.isInteger(rs)) {
        throw new TypeError('rs')
    }
    return rs - TAG_LENGTH - 1
}

/**
 * Number of ECE data records needed to hold `plaintextSize` bytes. Returns 0
 * for empty input — an empty stream encrypts to a header with no data records.
 *
 * @param plaintextSize Total plaintext length in bytes.
 * @param rs Record size in bytes (default RECORD_SIZE).
 * @returns Record count (0 when plaintextSize is 0).
 */
export function recordCount (
    plaintextSize:number,
    rs:number = RECORD_SIZE
):number {
    if (!Number.isInteger(plaintextSize)) {
        throw new TypeError('plaintextSize')
    }
    if (!Number.isInteger(rs)) {
        throw new TypeError('rs')
    }
    return Math.ceil(plaintextSize / recordPlaintextSize(rs))
}
```

`Math.ceil(0 / n)` is `0`, so `recordCount(0)` is `0` without special-casing.

**Testing:**
In `test/seekable-write.ts`, add tests verifying:
- seekable-write.AC4.1: `recordPlaintextSize()` equals `RECORD_SIZE - 17`
  (65519), and `recordPlaintextSize(1024)` equals `1007`.
- seekable-write.AC4.2: for `n > 0`, `recordCount(n, rs)` equals
  `Math.ceil(n / (rs - 17))`. Cover `n = 1` → `1`; `n = rs - 17` → `1`;
  `n = (rs - 17) + 1` → `2` (use a small `rs` like 1024 for legible numbers).
- seekable-write.AC4.3: `recordCount(0)` equals `0` (default rs and a custom rs).
- seekable-write.AC4.4 (count): `recordCount(3 * (rs - 17), rs)` equals `3`.

**Verification:**
Run: `npm test`
Expected: all geometry tests pass.

**Commit:** `feat(ece): add recordPlaintextSize and recordCount`
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Add header() and delegate createHeader to it

**Verifies:** seekable-write.AC3.1

**Files:**
- Modify: `src/ece.ts` (add `header` after the geometry helpers from Task 2)
- Modify: `src/ece.ts:154-161` (refactor `createHeader` to delegate)
- Test: `test/seekable-write.ts`

**Implementation:**
Add a module-level `header` function that is the single source of truth for the
21-byte header (`salt(16) || recordSize(uint32 BE) || idlen(0)`). It validates
salt length (so a bad salt to this low-level function throws `Invalid salt
length`, matching `ECETransformer`'s constructor). Function declarations are
hoisted, so `ECETransformer.createHeader` can call it even though `header` is
defined later in the file.

```ts
/**
 * Build the canonical 21-byte ECE header:
 * `salt(16) || recordSize(uint32 BE) || idlen(0)`.
 *
 * This is the single source of truth for the header; the streaming encoder
 * delegates to it, so a standalone header is byte-identical to the stream's
 * header.
 *
 * SAFETY: a fixed salt must never encrypt two different plaintexts under the
 * same key (AES-GCM nonce reuse). Prefer deriving the salt from the content
 * (see `deriveContentSalt`) over choosing it directly. This is a low-level
 * building block; the Keychain API does not accept a raw salt.
 *
 * @param salt 16-byte content salt.
 * @param rs Record size in bytes (default RECORD_SIZE).
 * @returns The 21-byte header.
 */
export function header (
    salt:Uint8Array<ArrayBuffer>,
    rs:number = RECORD_SIZE
):Uint8Array<ArrayBuffer> {
    if (salt.byteLength !== KEY_LENGTH) {
        throw new Error('Invalid salt length')
    }
    if (!Number.isInteger(rs)) {
        throw new TypeError('rs')
    }
    const buf = new Uint8Array(HEADER_LENGTH)
    buf.set(salt)
    const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
    dv.setUint32(KEY_LENGTH, rs)
    return buf
}
```

Then refactor `createHeader` (`src/ece.ts:154-161`) to delegate. Keep the
existing `Not salt` guard so behavior for a null salt is unchanged:

```ts
    createHeader ():Uint8Array {
        if (!this.salt) throw new Error('Not salt')
        return header(this.salt, this.rs)
    }
```

This is byte-identical to the previous inline implementation (same salt copy,
same big-endian `setUint32(KEY_LENGTH, rs)`, same zeroed idlen byte).

**Testing:**
In `test/seekable-write.ts`, add a test verifying:
- seekable-write.AC3.1: with a fixed 16-byte `salt` and a record size `rs`,
  `header(salt, rs)` equals the first `HEADER_LENGTH` (21) bytes emitted by
  `encryptStream(stream, key, rs, salt)`. Build the key with WebCrypto
  `importKey('raw', keyBytes, 'HKDF', false, ['deriveBits', 'deriveKey'])`
  (see helper in Task 4); feed some non-empty data through `arrayToStream`;
  collect output via `streamToArray`; assert
  `t.deepEqual(out.slice(0, HEADER_LENGTH), header(salt, rs))`.

**Verification:**
Run: `npm test`
Expected: the header-equality test passes.

**Commit:** `feat(ece): add canonical header() and delegate createHeader`
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Create test/seekable-write.ts and register it

**Verifies:** seekable-write.AC6.1 (partial), seekable-write.AC6.2 (plus it
hosts the tests from Tasks 2-3)

**Files:**
- Create: `test/seekable-write.ts`
- Modify: `test/index.ts` (add `import './seekable-write.js'`)

**Implementation:**
Create the test file with the standard tapzero setup and the helpers this
feature's tests need across all phases. Use this scaffold (the implementor adds
the individual `test(...)` blocks for Tasks 2-3 and the export-surface tests
below):

```ts
import { test } from '@substrate-system/tapzero'
import { webcrypto } from '@substrate-system/one-webcrypto'
import {
    RECORD_SIZE,
    HEADER_LENGTH,
    recordPlaintextSize,
    recordCount,
    header,
    encryptStream
} from '../src/ece.js'
import * as root from '../src/index.js'

// Build the HKDF CryptoKey that ece functions expect as `secretKey`.
async function makeKey (
    bytes:Uint8Array = webcrypto.getRandomValues(new Uint8Array(16))
):Promise<CryptoKey> {
    return webcrypto.subtle.importKey(
        'raw',
        bytes,
        'HKDF',
        false,
        ['deriveBits', 'deriveKey']
    )
}

function arrayToStream (array:Uint8Array):ReadableStream<Uint8Array> {
    return new ReadableStream({
        pull (controller) {
            controller.enqueue(array)
            controller.close()
        }
    })
}

async function streamToArray (
    stream:ReadableStream<Uint8Array>
):Promise<Uint8Array> {
    const response = new Response(stream)
    return new Uint8Array(await response.arrayBuffer())
}
```

Add the export-surface tests:
- seekable-write.AC6.1 (partial): assert the five Phase-1 names are importable
  from `'../src/ece.js'` — `typeof RECORD_SIZE === 'number'`,
  `typeof HEADER_LENGTH === 'number'` (and equals 21),
  `typeof recordPlaintextSize === 'function'`,
  `typeof recordCount === 'function'`, `typeof header === 'function'`.
  (Phase 2 extends this test to `deriveContentSalt` and `encryptRecord`.)
- seekable-write.AC6.2: assert the root surface does NOT expose any of the new
  names: for each of `RECORD_SIZE`, `HEADER_LENGTH`, `recordPlaintextSize`,
  `recordCount`, `header`, `deriveContentSalt`, `encryptRecord`, assert
  `typeof (root as Record<string, unknown>)[name] === 'undefined'`.

Register the file by adding to `test/index.ts` after the existing
`import './bytes.js'` line:

```ts
import './seekable-write.js'
```

**Testing:**
This task wires up the test file that hosts Tasks 2-3 tests plus the export
tests above. All assertions are described in their respective tasks.

**Verification:**
Run: `npm test`
Expected: the new `seekable-write` tests run and pass alongside the existing
suite. Run `npm run lint`; expected: no lint errors.

**Commit:** `test(ece): add seekable-write geometry, header, export tests`
<!-- END_TASK_4 -->

<!-- END_SUBCOMPONENT_A -->

---

## Phase 1 done when

- `RECORD_SIZE` and `HEADER_LENGTH` are exported from `src/ece.ts`.
- `recordPlaintextSize`, `recordCount`, and `header` exist, exported, with
  `Number.isInteger` guards and the empty-case `recordCount(0) === 0`.
- `createHeader` delegates to `header` with byte-identical output.
- `test/seekable-write.ts` exists, is registered in `test/index.ts`, and its
  geometry, header-equality, and export-surface tests pass under `npm test`.
- `npm run build` and `npm run lint` pass.
- Covers seekable-write.AC3.1, seekable-write.AC4, seekable-write.AC6.
