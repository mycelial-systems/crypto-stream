import { webcrypto } from '@bicycle-codes/one-webcrypto'

export function generateSalt (len:number):Uint8Array {
    const salt = new Uint8Array(len)
    webcrypto.getRandomValues(salt)
    return salt
}

/**
 * Return a `Uint8Array` of the given length filled with random bytes.
 * @param length Number of random bytes to return
 * @returns {Uint8Array}
 */
export function randomBuf (length:number):Uint8Array {
    return webcrypto.getRandomValues(new Uint8Array(length))
}

/**
 * Concatenate two buffers into a single `Uint8Array`.
 * @param fst The first buffer
 * @param snd The second buffer
 * @returns {Uint8Array}
 */
export function joinBufs (
    fst:ArrayBuffer|Uint8Array,
    snd:ArrayBuffer|Uint8Array
):Uint8Array {
    const view1 = new Uint8Array(fst)
    const view2 = new Uint8Array(snd)
    const joined = new Uint8Array(view1.length + view2.length)
    joined.set(view1)
    joined.set(view2, view1.length)
    return joined
}
