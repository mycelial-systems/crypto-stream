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
