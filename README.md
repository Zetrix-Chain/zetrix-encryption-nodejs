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

## License

[MIT](LICENSE)
