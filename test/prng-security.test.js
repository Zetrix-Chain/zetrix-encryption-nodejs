'use strict';

const { expect } = require('chai');
const path = require('path');
const { spawnSync } = require('child_process');
const KeyPair = require('../lib/keypair');

const CHILD = path.join(__dirname, 'fixtures', 'determinism-child.js');
const SIGN_CHILD = path.join(__dirname, 'fixtures', 'determinism-sign-child.js');

function generateInChildProcess(signType) {
  const result = spawnSync(process.execPath, [CHILD, signType], { encoding: 'utf8' });
  if (result.status !== 0) {
    throw new Error(`child process failed for signType=${signType}: ${result.stderr}`);
  }
  return JSON.parse(result.stdout);
}

function signInChildProcess(encPrivateKey, message) {
  const result = spawnSync(process.execPath, [SIGN_CHILD, encPrivateKey, message], { encoding: 'utf8' });
  if (result.status !== 0) {
    throw new Error(`sign child process failed: ${result.stderr}`);
  }
  return JSON.parse(result.stdout).sig;
}

describe('Key generation PRNG security', function() {
  this.timeout(20000);

  ['ed25519', 'sm2'].forEach((signType) => {
    it(`${signType}: two processes with identical Math.random/Date state do not produce the same private key`, function() {
      const first = generateInChildProcess(signType);
      const second = generateInChildProcess(signType);
      expect(first.rawPriv).to.not.deep.equal(second.rawPriv);
    });
  });

  // Not asserted on the whole hybrid rawPriv: the dilithium3 portion is
  // independently CSPRNG-safe (randombytes -> crypto.randomBytes) and would
  // mask a still-vulnerable embedded ed25519 seed, letting this pass for the
  // wrong reason. The dedicated slice(0, 32) test below isolates that seed.
  it('hybrid: the embedded ed25519 seed (first 32 bytes of rawPriv) is not reproducible either, independent of the dilithium3 portion', function() {
    const first = generateInChildProcess('hybrid');
    const second = generateInChildProcess('hybrid');
    expect(first.rawPriv.slice(0, 32)).to.not.deep.equal(second.rawPriv.slice(0, 32));
  });
});

describe('SM2 signing nonce PRNG security', function() {
  this.timeout(20000);

  it('two processes with identical Math.random/Date state do not produce the same SM2 signature for the same key and message', function() {
    const kp = new KeyPair('sm2');
    const encPrivateKey = kp.getEncPrivateKey();
    const message = 'determinism probe message';

    const first = signInChildProcess(encPrivateKey, message);
    const second = signInChildProcess(encPrivateKey, message);
    expect(first).to.not.equal(second);
  });
});
