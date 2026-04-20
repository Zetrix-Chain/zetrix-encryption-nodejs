zetrix-encryption-nodejs
=======

## zetrix-encryption-nodejs  Installation
```
npm install zetrix-encryption-nodejs --save
```

## zetrix-encryption-nodejs  Test
```
npm test
```

## zetrix-encryption-nodejs  Usage

```js
'use strict';

const encryption = require('zetrix-encryption-nodejs');

const KeyPair = encryption.keypair;
const signature = encryption.signature;
const keystore = encryption.keystore;

let kp = new KeyPair();
// Get encPrivateKey, encPublicKey, address
let encPrivateKey = kp.getEncPrivateKey();
let encPublicKey = kp.getEncPublicKey();
let address = kp.getAddress();


console.log('============= bof: ==============');
console.log(`EncPrivateKey is : ${encPrivateKey}`);
console.log(`EncPublicKey is : ${encPublicKey}`);
console.log(`Address hash is : ${address}`);
console.log('============= eof: ==============');

// Get keypair
let keypair = KeyPair.getKeyPair();

// Get encPublicKey
let encPublicKey = KeyPair.getEncPublicKey(encPrivateKey);

// Get address
let address = KeyPair.getAddress(encPublicKey);

// check encPrivateKey
KeyPair.checkEncPrivateKey(encPrivateKey);

// check encPublicKey
KeyPair.checkEncPublicKey(encPublicKey);

// check address
KeyPair.checkAddress(address);

// signature sign and verify
let sign = signature.sign('test', encPrivateKey);
let verify = signature.verify('test', sign, encPublicKey);

// keystore
keystore.encrypt(encPrivateKey, 'test', function(encData) {
  keystore.decrypt(encData, 'test', function(descData) {
    console.log(descData);
  });
});

```

## Supported algorithms

Pass one of the following strings to `new KeyPair(signType)` or `KeyPair.getKeyPair(signType)`:

| `signType`   | Sign-type byte | Address-type byte | Address prefix |
|--------------|----------------|-------------------|----------------|
| `ed25519` (default) | `0x01` | `0x01` | `ZTX3` |
| `sm2`               | `0x02` | `0x02` | `ZTX3` |
| `dilithium3`        | `0x05` | `0x04` | `ZTX4` |
| `hybrid` (ED25519 + Dilithium3) | `0x06` | `0x06` | `ZTX5` |

### Notes on the Dilithium3 variant

The bundled Dilithium3 implementation (`lib/vendor/dilithium3-fips204/`) uses FIPS 204 / ML-DSA-65 parameter sizes (private key 4032 B, public key 1952 B, signature 3309 B) but **omits the FIPS 204 message-domain-separation prefix**. Signatures produced by this library are interoperable with the deployed Zetrix blockchain but are **not interoperable with spec-compliant ML-DSA-65 verifiers**.

The sign-type byte (`0x05`) and address-type byte (`0x04`) intentionally differ for Dilithium3. The mismatch preserves a stable `ZTX4` address prefix while keeping the `0x04` sign-type slot reserved (it was previously used for CFCA and is no longer valid — see `lib/constants.js`).

### Hybrid mode

`hybrid` keys sign twice (ED25519 + Dilithium3) and verification requires **both** signatures to pass. This provides defence-in-depth: classical forgery requires breaking ED25519, and post-quantum forgery requires breaking Dilithium3.

## License

[MIT](LICENSE)
