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

## Crypto-module secret-logging lint guard

`npm run check:secrets` runs a custom ESLint rule (`eslint-rules/no-secret-logging.js`,
configured in `eslint.config.js`) over `lib/` (excluding `lib/vendor/`) that flags private
keys, salts, IVs, and similar secret-shaped values passed to `console.*`, embedded in a
thrown `Error`'s message, or attached as a property on an object that's later thrown or
logged. Run it locally with `npm run check:secrets` before committing -- this repo has no
CI pipeline configured yet, so nothing runs it automatically.

This is **best-effort defence in depth, not a complete static guarantee** -- no lint rule
can be. The rule's own header comment carries the authoritative, up-to-date list of what it
does and does not catch; as of this writing the known gaps are:

- The rule inspects the literal AST at the call/throw site only -- it does not trace a
  secret's value backward through an intervening local variable (`const s = privateKey;
  console.log(s)`, `const msg = 'bad ' + privateKey; throw new Error(msg)`).
- A secret thrown as a bare string/template/`String()` call rather than an Error instance
  (`throw 'bad ' + privateKey`, `` throw `bad ${privateKey}` ``, `throw String(privateKey)`).
- Only three sinks are checked at all: `console.*`, `process.stdout`/`stderr.write`, and
  Error-like constructors. A generic logger object (`logger.info(iv)`), the `debug` package,
  `process.emitWarning(...)`, and `assert()`/`assert.ok()` messages are not checked -- none
  of these are used anywhere in `lib/` today.
- Secret-shaped names outside its naming pattern (short/generic ones like `k`, `sk`, `kp`,
  `aesKey`, `derivedKey` were deliberately left out to avoid false-positive floods).
- `console`/method aliasing created by a plain assignment rather than a declaration, an
  assignment-expression destructure, `.bind(...)`, a plain declaration alias of
  `process.stdout` (`const out = process.stdout; out.write(iv)`), default/rest destructuring
  of `console`, or a destructure one level removed from `console`/`process` (e.g.
  `const { stdout } = process`).
- Logging methods beyond `log/error/warn/info/debug/trace/dir/table`: `console.assert`,
  `group`/`groupCollapsed`, `dirxml`, `timeLog`, `count`.
- An Error-like holder not recognised as such: `Reflect.set`/`Reflect.defineProperty`/
  `Object.defineProperties` on a holder, a secret passed directly in the constructor message
  of an Error subclass whose name doesn't end in "Error" (distinct from the already-covered
  case of attaching a secret as a property on a tracked holder), an alias of an
  already-tracked holder, or a nested property path.
- Logging reached through `.call()`/`.apply()`/`Reflect.apply`, a computed
  `process['stdout']`, or `require('process').stdout`.
- A secret thrown as a bare object literal, passed to an arbitrary callback that might
  itself log it, passed through `Promise.reject({...})`, passed as an extra argument to a
  function that itself logs it, or built by an opaque helper before being thrown.
- `Object.defineProperty`/`Object.assign` targets that aren't literally `Object.*` (e.g. a
  local alias of `Object`).

The companion runtime tests (`test/keystore-keypair-hardening.test.js`) cover `lib/keystore.js`
specifically: they capture five console methods (`log`/`error`/`warn`/`info`/`debug`, not
`assert`/`count`/`group`, and not `process.stdout`/`stderr.write`) around `encrypt`/`decrypt`/
`decrypt1`, and inspect thrown errors with `util.inspect(err, { showHidden: true })` -- so they
too see a secret attached as a non-enumerable property, the same as the lint rule's own
`Object.defineProperty` check above (which flags the value regardless of the descriptor's
`enumerable` setting). They do not cover `lib/keypair.js` or `lib/signature.js` at all.

## License

[MIT](LICENSE)
