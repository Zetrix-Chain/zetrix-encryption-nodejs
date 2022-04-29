'use strict';

var should = require('chai').should();
var encryption = require('../lib');

var KeyPair = encryption.keypair;
var signature = encryption.signature;
var keystore = encryption.keystore;

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
        console.log(`encData: ${encData.encrypted}`)
      keystore.decrypt(encData, 'test', function(descData) {
        // get encPrivateKey
        descData.should.be.a('string');
        descData.should.equal(kp.encPrivateKey);
      });
    });
  });

  it('test: keystore.encrypt', function() {
    let privatekey = 'privbxgNEmueqwyqbbdJsVEwAs9bYyN9pqEmthVA7QZeAGe8jbhMHVRD'
    keystore.encrypt(privatekey, 'asd123456', function(encData) {
      console.log(`encData: ${encData.encrypted}`)
    });
  });

  it('test: keystore.decrypt', function() {
    let encData = {"cypher_text":"VTJGc2RHVmtYMTgzTDFBRFpTQ2lIUmJEaW1GandOK2o3UUpxNEticmdSN1gxMFhOWXdoWmk4dk5aWjd3TGpQODdNeXRaL0pMV3oxOS9UQ2grRzlGbVl4OTFmQ1V0Witq","aesctr_iv":"4296bb17e8bc3dc62cccc5425d9681a0d2a9f4eca7a2293aef312ecc7267fe99b6ef76fa60d34adf9038bb7801993052b02112a4e2846493e3ce8e6f9619cd7c","scrypt_params":{"n":16384,"p":1,"r":8,"salt":"b415cec9d465da52c7966cebf2c2a4141999c20d8bc25b13ac3b63c494173817828a57bc2ac09709dbeb46b2182ffd8b5c069ff6401c8d823eedbfedeb1478d1de28fdaa3f42293d2a90e01c8c16756dd6a9a69d9af1dfc867ecf8054a80aa45a6aa53790be3c20d07f50efe506b82e5c5efb29bbe6aa2aa801eb66cbf848508"},"version":2}
    keystore.decrypt1(encData, 'asd123456', function(descData) {
      // get encPrivateKey
      console.log(descData)
    });
  });

  it('test: checkAddress', function() {
    var result = KeyPair.checkAddress('ZTX3SzrfC6o9g9UBFMsxEBfqYrpfQZbtSgwVi');
    result.should.equal(true);
  });

});
