# crypto stream
![tests](https://github.com/mycelial-systems/crypto-stream/actions/workflows/nodejs.yml/badge.svg)
[![module](https://img.shields.io/badge/module-ESM%2FCJS-blue?style=flat-square)](README.md)
[![types](https://img.shields.io/npm/types/@substrate-system/crypto-stream?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![Common Changelog](https://nichoth.github.io/badge/common-changelog.svg)](./CHANGELOG.md)
[![install size](https://flat.badgen.net/packagephobia/install/@substrate-system/crypto-stream?cache-control=no-cache)](https://packagephobia.com/result?p=@substrate-system/crypto-stream)
[![license](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE)

Streaming encryption for the browser, based on
[Encrypted Content-Encoding for HTTP (RFC 8188)](https://tools.ietf.org/html/rfc8188)

This uses the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).


<details><summary><h2>Contents</h2></summary>

<!-- toc -->

- [install](#install)
- [fork](#fork)
- [example](#example)
  * [example with blobs](#example-with-blobs)
- [API](#api)
  * [`new Keychain([key, [salt]])`](#new-keychainkey-salt)
  * [`keychain.key`](#keychainkey)
  * [`keychain.keyB64`](#keychainkeyb64)
  * [`keychain.salt`](#keychainsalt)
  * [`keychain.saltB64`](#keychainsaltb64)
  * [`keychain.authToken()`](#keychainauthtoken)
  * [`keychain.authTokenB64()`](#keychainauthtokenb64)
  * [`keychain.authHeader()`](#keychainauthheader)
  * [`keychain.setAuthToken(authToken)`](#keychainsetauthtokenauthtoken)
  * [`keychain.encryptStream(stream)`](#keychainencryptstreamstream)
  * [`keychain.decryptStream(encryptedStream)`](#keychaindecryptstreamencryptedstream)
  * [`keychain.decryptStreamRange(offset, length, totalEncryptedLength)`](#keychaindecryptstreamrangeoffset-length-totalencryptedlength)
  * [`keychain.encryptMeta(meta)`](#keychainencryptmetameta)
  * [`keychain.decryptMeta(ivEncryptedMeta)`](#keychaindecryptmetaivencryptedmeta)
  * [`keychain.encryptBytes(bytes)`](#keychainencryptbytesbytes)
  * [`keychain.decryptBytes(bytes)`](#keychaindecryptbytesbytes)
  * [`plaintextSize(encryptedSize)`](#plaintextsizeencryptedsize)
  * [`encryptedSize(plaintextSize)`](#encryptedsizeplaintextsize)
- [credits](#credits)

<!-- tocstop -->

</details>

## install
```sh
npm i -S @substrate-system/crypto-stream
```

## fork
This is a fork of [SocketDev/wormhole-crypto](https://github.com/SocketDev/wormhole-crypto). Thanks [@SocketDev](https://github.com/SocketDev) team for working in open source.

## example

```js
import { Keychain } from '@substrate-system/crypto-stream'

// Create a new keychain. Since no arguments are specified, the key and salt
// are generated.
const keychain = new Keychain()

// Get a WHATWG stream somehow, from fetch(), from a Blob(), etc.
const stream = getStream()

// Create an encrypted version of that stream
const encryptedStream = await keychain.encryptStream(stream)

// Normally you'd now use `encryptedStream`, e.g. in fetch(), etc.
// However, for this example, we'll just decrypt the stream immediately
const plaintextStream = await keychain.decryptStream(encryptedStream)

// Now, you can use `plaintextStream` and it will be identical
// to if you had used `stream`.
```

### example with blobs

See [./example](./example/index.ts) for a version that uses blobs + a
local `vite` server.

```js
import { Keychain } from '@substrate-system/crypto-stream'

const encryptedData = await fetch(imgUrl)
const decryptedStream = await keychain.decryptStream(encryptedData.body)
const response = new Response(decryptedStream)
const blobUrl = window.URL.createObjectURL(await response.blob())

// ...

function Component () {
    return html`<img src="${blobUrl}" />`
}
```

## API

### `new Keychain([key, [salt]])`
```ts
constructor (key?:string|Uint8Array, salt?:string|Uint8Array)
```

Type: `Class`

Returns: `Keychain`

Create a new keychain object. The keychain can be used to create encryption
streams, decryption streams, and to encrypt or decrypt a "metadata" buffer.

#### `key`

Type: `Uint8Array | string | null`

Default: `null`

The main key. This should be 16 bytes in length. If a `string` is given,
then it should be a base64-encoded string. If the argument is `null`, then a
key will be automatically generated.

#### `salt`

Type: `Uint8Array | string | null`

Default: `null`

The salt. This should be 16 bytes in length. If a `string` is given,
then it should be a base64-encoded string. If this argument is `null`, then a
salt will be automatically generated.

### `keychain.key`

```ts
key:Uint8Array
```

The main key.

### `keychain.keyB64`

```ts
keyB64:string
```

The main key as a base64url-encoded string.

### `keychain.salt`

```ts
salt:Uint8Array
```

The salt.

Implementation note: The salt is used to derive the (internal) metadata key and
authentication token.

### `keychain.saltB64`

```ts
saltB64:string
```
The salt as a base64-encoded string.

### `keychain.authToken()`
```ts
authToken ():Promise<ArrayBuffer>
```

Returns the authentication token. By default, the authentication token is
automatically derived from the main key using HKDF SHA-256.

The authentication token can be used to communicate with the server and
prove that the client has permission to fetch some data. Without a valid
authentication token, the server can reject the request.

Since the authentication token is derived from the main key, the client would
present it to the server as a "reader token" to prove that it is in possession
of the main key without revealing the main key to the server.

For destructive operations, the client should instead
present a "writer token", which is not derived from the main key but is provided
by the server. 

### `keychain.authTokenB64()`

```ts
authTokenB64 ():Promise<string>
```

Returns the authentication token as a base64-encoded string.

### `keychain.authHeader()`

```ts
authHeader ():Promise<string>
// => `Bearer sync-v1 ${authTokenB64}`
```

Returns a `Promise` that resolves to the HTTP header value to be provided to the server, as a base64 string. It contains the authentication token.

### `keychain.setAuthToken(authToken)`

```ts
setAuthToken (authToken:string|Uint8Array|null):void
```

Update the keychain authentication token to the given `authToken`.

#### `authToken`

Type: `Uint8Array | string | null`

Default: `null`

The authentication token. This should be 16 bytes in length. If a `string` is
given, then it should be a base64-encoded string. If this argument is `null`,
then an authentication token will be automatically generated.

### `keychain.encryptStream(stream)`

```ts
encryptStream (stream:ReadableStream):Promise<ReadableStream>
```

Type: `Function`

Returns: `Promise<ReadableStream>`

Returns a `Promise` that resolves to a `ReadableStream` encryption stream that
consumes the data in `stream` and returns an encrypted version. Data is
encrypted with [Encrypted Content-Encoding for HTTP (RFC 8188)](https://tools.ietf.org/html/rfc8188).

#### `stream`

Type: `ReadableStream`

A WHATWG readable stream used as a data source for the encrypted stream.

### `keychain.decryptStream(encryptedStream)`

Type: `Function`

Returns: `Promise<ReadableStream>`

Returns a `Promise` that resolves to a `ReadableStream` decryption stream that
consumes the data in `encryptedStream` and returns a plaintext version.

### `keychain.decryptStreamRange(offset, length, totalEncryptedLength)`

```ts
function decryptStreamRange (
    secretKey:CryptoKey,
    offset:number,
    length:number,
    totalEncryptedLength:number,
    rs:number = RECORD_SIZE
):{
    ranges:{ offset:number, length:number }[],
    decrypt:(streams:ReadableStream[])=>ReadableStream
}
```

Returns a `Promise` that resolves to a object containing `ranges`, which is
an array of objects containing `offset` and `length` integers specifying the
encrypted byte ranges that are needed to decrypt the client's specified range,
and a `decrypt` function.

Once the client has gathered a stream for each byte range in `ranges`,
the client should call `decrypt(streams)`, where `streams` is an array of
`ReadableStream` objects, one for each of the requested ranges. `decrypt`
will then return a `ReadableStream` containing the plaintext data for the
client's desired byte range.

#### `encryptedStream`

Type: `ReadableStream`

A WHATWG readable stream used as a data source for the plaintext stream.

### `keychain.encryptMeta(meta)`

```ts
encryptMeta (meta:Uint8Array):Promise<Uint8Array>
```

Returns a `Promise` that resolves to an encrypted version of `meta`. The
metadata is encrypted with AES-GCM.

Implementation note: The metadata key is automatically derived from the main
key using HKDF SHA-256. The value is not user-controlled.

Implementation note: The initialization vector (IV) is automatically generated
and included in the encrypted output. No need to generate it or to manage it
separately from the encrypted output.

#### `meta`

Type: `Uint8Array`

The metadata buffer to encrypt.

### `keychain.decryptMeta(ivEncryptedMeta)`
```ts
decryptMeta (ivEncryptedMeta:Uint8Array):Promise<Uint8Array>
```

Returns: `Promise<Uint8Array>`

Returns a `Promise` that resolves to a decrypted version of `encryptedMeta`.

#### `ivEncryptedMeta`

Type: `Uint8Array`

The encrypted metadata buffer to decrypt.

### `keychain.encryptBytes(bytes)`

```ts
async function encryptBytes (
    bytes:ArrayBuffer|Uint8Array,
    opts?:{ iv?:Uint8Array },
):Promise<Uint8Array>
```

Encrypt and return the given data in-memory, not using streams.

### `keychain.decryptBytes(bytes)`

```ts
async function decryptBytes (
    bytes:Uint8Array,
):Promise<ArrayBuffer>
```

Decrypt the given data in-memory, without streaming.

### `plaintextSize(encryptedSize)`

```ts
function plaintextSize (
  encryptedSize:number,
  rs:number = RECORD_SIZE
):number
```

Given an encrypted size, return the corresponding plaintext size.

### `encryptedSize(plaintextSize)`
```ts
function encryptedSize (
  plaintextSize:number,
  rs:number = RECORD_SIZE
):number
```

Given a plaintext size, return the corresponding encrypted size.

## credits

Thank you [Feross](https://github.com/feross) and [SocketDev](https://github.com/SocketDev) team for writing and publishing this.
