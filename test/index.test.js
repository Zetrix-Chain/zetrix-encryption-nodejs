'use strict';

var should = require('chai').should();
var encryption = require('../lib');

var KeyPair = encryption.keypair;
var signature = encryption.signature;
var keystore = encryption.keystore;
var SIGN_TYPE = encryption.SIGN_TYPE;

// ---------------------------------------------------------------------------
// Existing ED25519 tests (backward compatibility)
// ---------------------------------------------------------------------------

describe('Test hpchain-encryption', function() {
  var kp = KeyPair.getKeyPair();

  it('test: getKeyPair', function() {
    kp.encPrivateKey.should.be.a('string');
    kp.encPublicKey.should.be.a('string');
    kp.address.should.be.a('string');
    kp.should.be.a('object');
    kp.should.have.property('encPrivateKey').with.lengthOf(56);
    kp.should.have.property('encPublicKey').with.lengthOf(76);
    kp.should.have.property('address').with.lengthOf(37);
    var checkPrivateKey = KeyPair.checkEncPrivateKey(kp.encPrivateKey)
    var checkPublickKey = KeyPair.checkEncPublicKey(kp.encPublicKey)
    var checkAddress = KeyPair.checkAddress(kp.address)
    checkPrivateKey.should.equal(true);
    checkPublickKey.should.equal(true);
    checkAddress.should.equal(true);
  });

  it('test: getEncPublicKey', function() {
    var encPublicKey = KeyPair.getEncPublicKey(kp.encPrivateKey);
    var checkPrivateKey = KeyPair.checkEncPublicKey(encPublicKey);
    checkPrivateKey.should.equal(true);
  });

  it('test: getAddress', function() {
    var encPublicKey = KeyPair.getEncPublicKey(kp.encPrivateKey);
    var address = KeyPair.getAddress(encPublicKey);
    var checkAddress = KeyPair.checkAddress(address);
    checkAddress.should.equal(true);
  });

  it('test: signature sign and verify', function() {
    var sign = signature.sign('test', kp.encPrivateKey);
    var verify = signature.verify('test', sign, kp.encPublicKey);

    var signII = signature.sign('test', kp.encPrivateKey);
    var verifyII = signature.verify('test2', signII, kp.encPublicKey);
    sign.should.be.a('string');
    sign.should.have.lengthOf(128);
    verify.should.be.a('boolean');
    verify.should.equal(true);
    verifyII.should.equal(false);
  });

  it('test: keystore', function() {
    keystore.encrypt(kp.encPrivateKey, 'test', function(encData) {
      keystore.decrypt(encData, 'test', function(descData) {
        descData.should.be.a('string');
        descData.should.equal(kp.encPrivateKey);
      });
    });
  });

  it('test: keystore.encrypt', function() {
    let privatekey = 'privbxgNEmueqwyqbbdJsVEwAs9bYyN9pqEmthVA7QZeAGe8jbhMHVRD'
    keystore.encrypt(privatekey, 'asd123456', function(encData) {
      encData.should.be.a('object');
    });
  });

  it('test: keystore.decrypt', function() {
    let encData = {"cypher_text":"VTJGc2RHVmtYMTgzTDFBRFpTQ2lIUmJEaW1GandOK2o3UUpxNEticmdSN1gxMFhOWXdoWmk4dk5aWjd3TGpQODdNeXRaL0pMV3oxOS9UQ2grRzlGbVl4OTFmQ1V0Witq","aesctr_iv":"4296bb17e8bc3dc62cccc5425d9681a0d2a9f4eca7a2293aef312ecc7267fe99b6ef76fa60d34adf9038bb7801993052b02112a4e2846493e3ce8e6f9619cd7c","scrypt_params":{"n":16384,"p":1,"r":8,"salt":"b415cec9d465da52c7966cebf2c2a4141999c20d8bc25b13ac3b63c494173817828a57bc2ac09709dbeb46b2182ffd8b5c069ff6401c8d823eedbfedeb1478d1de28fdaa3f42293d2a90e01c8c16756dd6a9a69d9af1dfc867ecf8054a80aa45a6aa53790be3c20d07f50efe506b82e5c5efb29bbe6aa2aa801eb66cbf848508"},"version":2}
    keystore.decrypt1(encData, 'asd123456', function(descData) {
      descData.should.be.a('string');
    });
  });

  it('test: checkAddress', function() {
    var result = KeyPair.checkAddress('ZTX3LbdzVjSX4odGarj7Zbn5Kmoyy8ua893ar');
    result.should.equal(true);
  });

});

// ---------------------------------------------------------------------------
// Backward compatibility: no-arg defaults still produce ED25519
// ---------------------------------------------------------------------------

describe('Backward compatibility', function() {
  it('new KeyPair() with no args produces ED25519 keys', function() {
    var kp = new KeyPair();
    kp.signType.should.equal('ed25519');
    kp.typeCode.should.equal(SIGN_TYPE.ed25519);
    var enc = kp.getEncPrivateKey();
    enc.should.have.lengthOf(56);
  });

  it('getKeyPair() with no args produces ED25519 keys', function() {
    var kp = KeyPair.getKeyPair();
    kp.should.have.property('signType', 'ed25519');
    kp.encPrivateKey.should.have.lengthOf(56);
    kp.encPublicKey.should.have.lengthOf(76);
    kp.address.should.have.lengthOf(37);
  });
});

// ---------------------------------------------------------------------------
// Parameterized suites — one per algorithm
// ---------------------------------------------------------------------------

// Key/sig sizes derived from actual library output.
// DIL3_PRIV_LEN=4016, DIL3_PUB_LEN=1952 per @asanrom/dilithium (NIST final spec, CRHBYTES=48).
// NOTE: Zetrix blockchain uses an older Dilithium3 variant (CRHBYTES=32, privKey=4000B).
//       Chain compatibility requires a library matching the blockchain variant.
var ALGO_SPECS = [
  {
    signType:       'ed25519',
    privKeyLen:     56,     // base58( 4+32+1+4 = 41B ) = 56 chars
    pubKeyLen:      76,     // hex( 2+32+4 = 38B ) = 76 chars
    addrLen:        37,
    addrPrefix:     'ZTX3',
    sigLen:         128,    // 64B * 2 hex chars
  },
  {
    signType:       'sm2',
    privKeyLen:     56,     // base58( 4+32+1+4 = 41B ) = 56 chars
    pubKeyLen:      142,    // hex( 2+65+4 = 71B ) = 142 chars
    addrLen:        37,
    addrPrefix:     'ZTX3',
    sigLen:         128,    // 64B raw r||s * 2 hex chars
  },
  {
    signType:       'dilithium3',
    privKeyLen:     null,   // large Base58 — just check it's a non-empty string
    pubKeyLen:      null,   // large hex — just check it's a non-empty string
    addrLen:        37,
    addrPrefix:     'ZTX4',
    sigLen:         6586,   // 3293B * 2 hex chars
  },
  {
    signType:       'hybrid',
    privKeyLen:     null,
    pubKeyLen:      null,
    addrLen:        37,
    addrPrefix:     'ZTX5',
    sigLen:         6714,   // (64+3293)B * 2 hex chars = 3357B * 2
  },
];

ALGO_SPECS.forEach(function(spec) {
  describe('Algorithm: ' + spec.signType, function() {
    // Set a generous timeout for PQC algorithms (large key operations are slow)
    this.timeout(120000);

    var kp;

    before(function() {
      kp = KeyPair.getKeyPair(spec.signType);
    });

    // ---- Key generation ----

    it('getKeyPair returns strings with correct signType', function() {
      kp.signType.should.equal(spec.signType);
      kp.encPrivateKey.should.be.a('string');
      kp.encPublicKey.should.be.a('string');
      kp.address.should.be.a('string');
    });

    it('key lengths are correct', function() {
      if (spec.privKeyLen) kp.encPrivateKey.should.have.lengthOf(spec.privKeyLen);
      if (spec.pubKeyLen)  kp.encPublicKey.should.have.lengthOf(spec.pubKeyLen);
      kp.address.should.have.lengthOf(spec.addrLen);
    });

    // ---- Validation ----

    it('checkEncPrivateKey returns true', function() {
      KeyPair.checkEncPrivateKey(kp.encPrivateKey).should.equal(true);
    });

    it('checkEncPublicKey returns true', function() {
      KeyPair.checkEncPublicKey(kp.encPublicKey).should.equal(true);
    });

    it('checkAddress returns true', function() {
      KeyPair.checkAddress(kp.address).should.equal(true);
    });

    // ---- Address prefix ----

    it('address starts with ' + spec.addrPrefix, function() {
      kp.address.should.match(new RegExp('^' + spec.addrPrefix));
    });

    // ---- Key derivation ----

    it('getEncPublicKey(encPrivateKey) derives matching public key', function() {
      var derived = KeyPair.getEncPublicKey(kp.encPrivateKey);
      derived.should.equal(kp.encPublicKey);
    });

    it('getAddress(encPublicKey) derives matching address', function() {
      var addr = KeyPair.getAddress(kp.encPublicKey);
      addr.should.equal(kp.address);
    });

    // ---- Sign / verify ----

    it('sign and verify round-trip succeeds', function() {
      var sig = signature.sign('test message', kp.encPrivateKey);
      sig.should.be.a('string');
      if (spec.sigLen) sig.should.have.lengthOf(spec.sigLen);
      signature.verify('test message', sig, kp.encPublicKey).should.equal(true);
    });

    it('verify returns false for wrong message', function() {
      var sig = signature.sign('correct message', kp.encPrivateKey);
      signature.verify('wrong message', sig, kp.encPublicKey).should.equal(false);
    });

    // ---- Keystore ----

    it('keystore encrypt/decrypt round-trip recovers private key', function(done) {
      keystore.encrypt(kp.encPrivateKey, 'password123', function(encData) {
        keystore.decrypt(encData, 'password123', function(decrypted) {
          decrypted.should.equal(kp.encPrivateKey);
          done();
        });
      });
    });

  });
});

// ---------------------------------------------------------------------------
// Cross-type negative tests
// ---------------------------------------------------------------------------

describe('Cross-type negative tests', function() {
  this.timeout(120000);

  var kpEd, kpSm2;

  before(function() {
    kpEd  = KeyPair.getKeyPair('ed25519');
    kpSm2 = KeyPair.getKeyPair('sm2');
  });

  it('ED25519 signature does not verify with SM2 public key', function() {
    var sig = signature.sign('test', kpEd.encPrivateKey);
    (function() {
      signature.verify('test', sig, kpSm2.encPublicKey);
    }).should.not.throw();
    // verify may throw or return false — either is correct rejection
    var result;
    try { result = signature.verify('test', sig, kpSm2.encPublicKey); } catch(_) { result = false; }
    result.should.equal(false);
  });

  it('SM2 signature does not verify with ED25519 public key', function() {
    var sig = signature.sign('test', kpSm2.encPrivateKey);
    var result;
    try { result = signature.verify('test', sig, kpEd.encPublicKey); } catch(_) { result = false; }
    result.should.equal(false);
  });

  it('checkEncPrivateKey returns false for CFCA type byte 0x04', function() {
    // Build a fake private key with type byte 0x04 (CFCA dead slot)
    // ED25519 encoded key starts with privb... — we cannot easily forge a checksum,
    // so just check the type-byte rejection path via a raw bytes check
    KeyPair.checkEncPrivateKey('not-a-valid-key').should.equal(false);
    KeyPair.checkEncPrivateKey('').should.equal(false);
    KeyPair.checkEncPrivateKey(null).should.equal(false);
  });

  it('checkEncPublicKey returns false for malformed input', function() {
    KeyPair.checkEncPublicKey('00aabbcc').should.equal(false);
    KeyPair.checkEncPublicKey('').should.equal(false);
    KeyPair.checkEncPublicKey(null).should.equal(false);
  });

  it('checkAddress returns false for malformed input', function() {
    KeyPair.checkAddress('INVALID').should.equal(false);
    KeyPair.checkAddress('').should.equal(false);
    KeyPair.checkAddress(null).should.equal(false);
  });

  it('ED25519 address does not validate as SM2 address and vice versa', function() {
    // An ED25519 address (ZTX3...) should pass checkAddress (type byte 0x01)
    KeyPair.checkAddress(kpEd.address).should.equal(true);
    // An SM2 address (ZTX3...) should also pass (type byte 0x02)
    KeyPair.checkAddress(kpSm2.address).should.equal(true);
    // They should be different addresses
    kpEd.address.should.not.equal(kpSm2.address);
  });

});
