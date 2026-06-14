import { FunctionComponent, render } from 'preact'
import { signal, computed, effect } from '@preact/signals'
import { html } from 'htm/preact'
import { Keychain } from '../src/keychain.js'
import Debug from '@substrate-system/debug'
const debug = Debug()

// Create a new keychain. Since no arguments are specified, the key
// and salt are generated.
const keychain = new Keychain()

// Get a WHATWG stream somehow, from fetch(), from a Blob(), etc.
const imgUrl = new URL('/cheesecake.jpeg', import.meta.url).href
const requestForImg = await fetch(imgUrl)

// Create an encrypted version of that stream
const encryptedSignal = signal<ReadableStream|null>(null)
const encryptedImg = await keychain.encryptStream(requestForImg.body!)
encryptedSignal.value = encryptedImg

const decryptedSignal = signal<null|Blob>(null)

effect(() => {
    if (!encryptedSignal.value) return

    (async () => {
        // Normally you'd now use `encryptedStream`, e.g. in fetch(), etc.
        // However, for this example, we'll just decrypt the stream immediately
        const decryptedStream = await keychain.decryptStream(encryptedImg)
        const decryptedReader = decryptedStream.getReader()
        const { value } = await decryptedReader.read()
        decryptedSignal.value = new Blob([new Uint8Array(value!)])
    })()
})

/**
 * If a chunk is available to read, the promise will be fulfilled with an
 * object of the form { value: theChunk, done: false }.
 *
 * https://developer.mozilla.org/en-US/docs/Web/API/Streams_API/Using_readable_streams#reading_the_stream
 */

const blobUrl = computed<string|null>(() => {
    if (!decryptedSignal.value) return null
    const blobUrl = window.URL.createObjectURL(decryptedSignal.value)
    return blobUrl
})

const Example:FunctionComponent = function Example () {
    debug('rendering...', blobUrl.value)

    return html`<div>
        <p>The cheesecake.jpeg, linked as unencrypted file:</p>
        <img src="${imgUrl}" />

        <p>
            Cheesecake, after requesting via <code>fetch</code>, encrypting,
            then decrypting:
        </p>

        <img src="${blobUrl.value}" />
    </div>`
}

render(html`<${Example} />`, document.getElementById('root')!)
