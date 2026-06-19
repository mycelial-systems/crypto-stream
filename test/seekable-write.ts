import { test } from '@substrate-system/tapzero'
import { webcrypto } from '@substrate-system/one-webcrypto'
import {
    RECORD_SIZE,
    HEADER_LENGTH,
    recordPlaintextSize,
    recordCount,
    header,
    encryptStream,
    decryptStream,
    deriveContentSalt,
    encryptRecord
} from '../src/ece.js'
import * as root from '../src/index.js'

// Build the HKDF CryptoKey that ece functions expect as `secretKey`.
async function makeKey (
    bytes:Uint8Array<ArrayBuffer> = webcrypto.getRandomValues(new Uint8Array(16))
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

// Export surface tests (AC6)
test('exports: RECORD_SIZE', t => {
    t.equal(typeof RECORD_SIZE, 'number')
})

test('exports: HEADER_LENGTH', t => {
    t.equal(typeof HEADER_LENGTH, 'number')
    t.equal(HEADER_LENGTH, 21)
})

test('exports: recordPlaintextSize', t => {
    t.equal(typeof recordPlaintextSize, 'function')
})

test('exports: recordCount', t => {
    t.equal(typeof recordCount, 'function')
})

test('exports: header', t => {
    t.equal(typeof header, 'function')
})

test('root exports: should not have seekable-write exports', t => {
    const names = [
        'RECORD_SIZE',
        'HEADER_LENGTH',
        'recordPlaintextSize',
        'recordCount',
        'header',
        'deriveContentSalt',
        'encryptRecord'
    ]
    for (const name of names) {
        t.equal(
            typeof (root as Record<string, unknown>)[name],
            'undefined',
            `root.${name} should be undefined`
        )
    }
})

// Geometry tests (AC4)
test('recordPlaintextSize: default record size', t => {
    const result = recordPlaintextSize()
    t.equal(result, RECORD_SIZE - 17)
    t.equal(result, 65519)
})

test('recordPlaintextSize: custom record size', t => {
    const result = recordPlaintextSize(1024)
    t.equal(result, 1007)
})

test('recordCount: n=1 with custom rs', t => {
    const rs = 1024
    const n = 1
    const result = recordCount(n, rs)
    t.equal(result, 1)
})

test('recordCount: n=rs-17 with custom rs', t => {
    const rs = 1024
    const n = rs - 17
    const result = recordCount(n, rs)
    t.equal(result, 1)
})

test('recordCount: n=(rs-17)+1 with custom rs', t => {
    const rs = 1024
    const n = (rs - 17) + 1
    const result = recordCount(n, rs)
    t.equal(result, 2)
})

test('recordCount: zero plaintext with default rs', t => {
    const result = recordCount(0)
    t.equal(result, 0)
})

test('recordCount: zero plaintext with custom rs', t => {
    const result = recordCount(0, 1024)
    t.equal(result, 0)
})

test('recordCount: k*(rs-17) records with custom rs', t => {
    const rs = 1024
    const k = 3
    const n = k * (rs - 17)
    const result = recordCount(n, rs)
    t.equal(result, k)
})

// Header equality test (AC3.1)
test('header: matches encryptStream output', async t => {
    const salt = webcrypto.getRandomValues(new Uint8Array(16))
    const rs = 4096
    const key = await makeKey()

    // Build standalone header
    const standaloneHeader = header(salt, rs)

    // Build encrypted stream with same salt and rs
    const plaintext = new Uint8Array([1, 2, 3, 4, 5])
    const encrypted = await streamToArray(
        encryptStream(arrayToStream(plaintext), key, rs, salt)
    )

    // Extract first 21 bytes from encrypted stream
    const streamHeader = encrypted.slice(0, HEADER_LENGTH)

    // Compare
    t.deepEqual(standaloneHeader, streamHeader)
})

// deriveContentSalt tests (AC2.3, AC2.2, AC5.3)
test('deriveContentSalt: deterministic for same (key, digest)', async t => {
    const key = await makeKey()
    const digest = new Uint8Array(32).fill(7)

    const salt1 = await deriveContentSalt(key, digest)
    const salt2 = await deriveContentSalt(key, digest)

    t.equal(salt1.byteLength, 16)
    t.equal(salt2.byteLength, 16)
    t.deepEqual(salt1, salt2)
})

test('deriveContentSalt: different digests yield different salts', async t => {
    const key = await makeKey()
    const digest1 = new Uint8Array(32).fill(1)
    const digest2 = new Uint8Array(32).fill(2)

    const salt1 = await deriveContentSalt(key, digest1)
    const salt2 = await deriveContentSalt(key, digest2)

    t.equal(salt1.byteLength, 16)
    t.equal(salt2.byteLength, 16)
    const equal = salt1.every((v, i) => v === salt2[i])
    t.ok(!equal, 'different digests should produce different salts')
})

test('deriveContentSalt: rejects empty digest', async t => {
    const key = await makeKey()
    const emptyDigest = new Uint8Array(0)

    await t.throws(async () => {
        await deriveContentSalt(key, emptyDigest)
    })
})

// encryptRecord tests (AC5.1, AC5.2, AC5.4)
test('encryptRecord: non-final record with wrong length throws', async t => {
    const key = await makeKey()
    const rs = 64
    const max = recordPlaintextSize(rs)
    const salt = webcrypto.getRandomValues(new Uint8Array(16))
    const slice = new Uint8Array(max - 1)

    await t.throws(async () => {
        await encryptRecord(key, 0, slice, false, salt, rs)
    })
})

test('encryptRecord: final record with oversized slice throws', async t => {
    const key = await makeKey()
    const rs = 64
    const max = recordPlaintextSize(rs)
    const salt = webcrypto.getRandomValues(new Uint8Array(16))
    const slice = new Uint8Array(max + 1)

    await t.throws(async () => {
        await encryptRecord(key, 0, slice, true, salt, rs)
    })
})

test('encryptRecord: non-16-byte salt throws Invalid salt length', async t => {
    const key = await makeKey()
    const rs = 64
    const max = recordPlaintextSize(rs)
    const slice = new Uint8Array(max)
    const badSalt = new Uint8Array(15)

    await t.throws(async () => {
        await encryptRecord(key, 0, slice, false, badSalt, rs)
    }, /Invalid salt length/)
})

// Helper to build per-record ciphertext
async function buildPerRecordCiphertext (
    plaintext:Uint8Array,
    key:CryptoKey,
    salt:Uint8Array<ArrayBuffer>,
    rs:number
):Promise<Uint8Array> {
    const max = recordPlaintextSize(rs)
    const count = recordCount(plaintext.byteLength, rs)

    const chunks:Array<Uint8Array> = []

    chunks.push(header(salt, rs))

    for (let i = 0; i < count; i++) {
        const start = i * max
        const end = Math.min(start + max, plaintext.byteLength)
        const slice = plaintext.subarray(start, end)
        const isLast = i === count - 1

        const encrypted = await encryptRecord(key, i, slice, isLast, salt, rs)
        chunks.push(encrypted)
    }

    const totalSize = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0)
    const result = new Uint8Array(totalSize)
    let offset = 0
    for (const chunk of chunks) {
        result.set(chunk, offset)
        offset += chunk.byteLength
    }

    return result
}

// Record/stream equivalence tests (AC3.2, AC4.4)
test('record/stream equivalence: partial final record', async t => {
    const key = await makeKey()
    const rs = 256
    const salt = webcrypto.getRandomValues(new Uint8Array(16))
    const plaintext = new Uint8Array(100)
    webcrypto.getRandomValues(plaintext)

    const perRecord = await buildPerRecordCiphertext(plaintext, key, salt, rs)
    const streamed = await streamToArray(
        encryptStream(arrayToStream(plaintext), key, rs, salt)
    )

    t.deepEqual(perRecord, streamed)
})

test('record/stream equivalence: single full record', async t => {
    const key = await makeKey()
    const rs = 256
    const salt = webcrypto.getRandomValues(new Uint8Array(16))
    const max = recordPlaintextSize(rs)
    const plaintext = new Uint8Array(max)
    webcrypto.getRandomValues(plaintext)

    const perRecord = await buildPerRecordCiphertext(plaintext, key, salt, rs)
    const streamed = await streamToArray(
        encryptStream(arrayToStream(plaintext), key, rs, salt)
    )

    t.deepEqual(perRecord, streamed)
})

test('record/stream equivalence: multiple records non-multiple', async t => {
    const key = await makeKey()
    const rs = 256
    const salt = webcrypto.getRandomValues(new Uint8Array(16))
    const max = recordPlaintextSize(rs)
    const plaintext = new Uint8Array(max * 2 + 50)
    webcrypto.getRandomValues(plaintext)

    const perRecord = await buildPerRecordCiphertext(plaintext, key, salt, rs)
    const streamed = await streamToArray(
        encryptStream(arrayToStream(plaintext), key, rs, salt)
    )

    t.deepEqual(perRecord, streamed)
})

test('record/stream equivalence: exact multiple (k*(rs-17))', async t => {
    const key = await makeKey()
    const rs = 256
    const salt = webcrypto.getRandomValues(new Uint8Array(16))
    const max = recordPlaintextSize(rs)
    const k = 3
    const plaintext = new Uint8Array(k * max)
    webcrypto.getRandomValues(plaintext)

    const perRecord = await buildPerRecordCiphertext(plaintext, key, salt, rs)
    const streamed = await streamToArray(
        encryptStream(arrayToStream(plaintext), key, rs, salt)
    )

    t.deepEqual(perRecord, streamed)
})

// Round-trip test (AC3.3)
test('record/stream: round-trip decryption', async t => {
    const key = await makeKey()
    const rs = 256
    const salt = webcrypto.getRandomValues(new Uint8Array(16))
    const max = recordPlaintextSize(rs)
    const plaintext = new Uint8Array(max * 2 + 50)
    webcrypto.getRandomValues(plaintext)

    const perRecord = await buildPerRecordCiphertext(plaintext, key, salt, rs)

    const decrypted = await streamToArray(
        decryptStream(arrayToStream(perRecord), key, rs)
    )

    t.deepEqual(decrypted, plaintext)
})

// Export surface completion test (AC6.1)
test('exports: deriveContentSalt', t => {
    t.equal(typeof deriveContentSalt, 'function')
})

test('exports: encryptRecord', t => {
    t.equal(typeof encryptRecord, 'function')
})
