# Human Test Plan — Seekable Write

This is a library-only change: deterministic crypto and geometry functions
with no UI. The automated suite exhaustively covers all 22 acceptance criteria
(`seekable-write.AC*`). The requirements doc explicitly states no human
verification is needed for any AC. The only meaningful manual activity is a
non-blocking published-package sanity check, plus a maintainer-side
confirmation that the suite is green. There are no end-to-end UI scenarios and
no edge cases that benefit from human judgment beyond what the automated tests
already assert.

## Prerequisites

- Node.js installed; repo checked out at the merged feature HEAD.
- Run `npm install` if dependencies are not yet installed.
- `npm test` passing (expected: `total: 105`, `passing: 105`, `failing: 0`).

## Phase 1: Suite confirmation (maintainer)

| Step | Action | Expected |
|------|--------|----------|
| 1 | From the repo root, run `npm test`. | Output ends with `total: 105`, `passing: 105`; no `not ok` / failing lines. |
| 2 | Confirm the seekable-write group ran by checking for test names like `contentDigest`, `record/stream equivalence`, `recordCount`, `Keychain round-trip`. | These appear in the output, confirming the suite was not partially skipped. |

## Human Verification Required

| Criterion | Why Manual | Steps |
|-----------|------------|-------|
| None (no AC requires human verification) | All 22 ACs are deterministic crypto/geometry properties fully covered by automated tests. | N/A |

## Optional (non-blocking): Published subpath smoke check

Purpose: confirm the published package exposes the low-level building blocks at
the documented subpath. The in-repo AC6.1 test already verifies these imports
against source; this only validates packaging/resolution after publish.

Steps:

1. In a scratch downstream project, install the published package
   (`npm install @substrate-system/crypto-stream`).
2. Import from the subpath:
   ```ts
   import {
       RECORD_SIZE, HEADER_LENGTH, recordPlaintextSize,
       recordCount, header, deriveContentSalt, encryptRecord
   } from '@substrate-system/crypto-stream/src/ece'
   ```
3. Expected: the import resolves without error; `typeof RECORD_SIZE === 'number'`,
   `HEADER_LENGTH === 21`, and the five functions are `function`.

Note: the requirements doc references the `/src/ece` subpath here while the
in-repo tests import from `../src/ece.js`; confirm the actually-published
subpath name matches `package.json` `exports` before relying on it.

## Traceability

| Acceptance Criterion | Automated Test | Manual Step |
|----------------------|----------------|-------------|
| AC1.1–AC1.4 | test/seekable-write.ts (encryptStream reproducible / random-salt / recordSize / empty) | Phase 1 |
| AC2.1–AC2.4 | test/seekable-write.ts (contentDigest + deriveContentSalt tests) | Phase 1 |
| AC3.1–AC3.4 | test/seekable-write.ts (header equality, record/stream equivalence, round-trips) | Phase 1 |
| AC4.1–AC4.4 | test/seekable-write.ts (recordPlaintextSize, recordCount, exact-multiple equivalence) | Phase 1 |
| AC5.1–AC5.4 | test/seekable-write.ts (encryptRecord + deriveContentSalt rejection tests) | Phase 1 |
| AC6.1 | test/seekable-write.ts (exports: * tests) | Phase 1 + Optional subpath smoke check |
| AC6.2 | test/seekable-write.ts (root exports exclusion test) | Phase 1 |

## Relevant file paths

- `docs/implementation-plans/2026-06-19-seekable-write/test-requirements.md`
- `test/seekable-write.ts`
- `test/index.ts` (registers the seekable-write suite)
- `src/ece.ts` (source of the seven low-level exports)
- `src/index.ts` (root export surface — confirms AC6.2)
- `src/keychain.ts` (Keychain digest API: `contentDigest`, `encryptStream`,
  `header`, `encryptRecord`, `decryptStream`)
