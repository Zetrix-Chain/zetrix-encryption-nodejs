'use strict';

const is = require('is-type-of');
const nacl = require('./vendor/nacl');
const sjcl = require('./vendor/sjcl');
const { sm2 } = require('sm-crypto');
const { Dilithium3 } = require('@asanrom/dilithium');
const KeyPair = require('./keypair');
const { SIGN_TYPE } = require('./constants');

const signature = {};

// Convert a message to a char-code Uint8Array consistent with nacl behavior
const msgToBytes = (msg) => {
  if (typeof msg === 'string') {
    return Uint8Array.from(msg.split('').map(c => c.charCodeAt(0)));
  }
  return msg instanceof Uint8Array ? msg : new Uint8Array(msg);
};

const hexToBytes = (hex) => {
  const out = [];
  for (let i = 0; i < hex.length; i += 2) {
    out.push(parseInt(hex.substring(i, i + 2), 16));
  }
  return out;
};

const bytesToHex = (bytes) =>
  Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');

/**
 * Sign a message with an encoded private key.
 *
 * @param {String|Uint8Array} message
 * @param {String} encPrivateKey
 * @returns {String} hex-encoded signature
 */
signature.sign = (message, encPrivateKey) => {
  if (!message || !encPrivateKey) {
    throw new Error('require message or encPrivateKey');
  }
  const { type, rawBytes } = KeyPair.parsePrivateKey(encPrivateKey);

  switch (type) {
    case SIGN_TYPE.ed25519: {
      const kp       = nacl.sign.keyPair.fromSeed(rawBytes);
      const signData = nacl.sign.detached(message, kp.secretKey);
      return sjcl.codec.hex.fromBits(sjcl.codec.bytes.toBits(signData));
    }

    case SIGN_TYPE.sm2: {
      // SM3withSM2 — sm-crypto handles ZA + SM3 pre-hash internally
      // { hash: true } = pre-hash with SM3 (compatible with OpenSSL SM3withSM2 default userId)
      // { der: false }  = raw r||s output (32B+32B = 64B), no DER
      const privHex = bytesToHex(rawBytes);
      return sm2.doSignature(message, privHex, { hash: true, der: false });
    }

    case SIGN_TYPE.dilithium3: {
      // rawBytes = dil3_priv(4000B) || dil3_pub(1952B)
      // Signing uses only the first 4000B (private key)
      const privKey = new Uint8Array(rawBytes.slice(0, 4000));
      const sig = Dilithium3.sign(msgToBytes(message), privKey);
      return bytesToHex(sig);
    }

    case SIGN_TYPE.hybrid: {
      // rawBytes = ed25519_seed(32B) || dil3_priv(4000B) || dil3_pub(1952B)
      const msgBytes = msgToBytes(message);

      // ED25519 sign
      const edKP    = nacl.sign.keyPair.fromSeed(new Uint8Array(rawBytes.slice(0, 32)));
      const edSig   = Array.from(nacl.sign.detached(msgBytes, edKP.secretKey)); // 64B

      // Dilithium3 sign
      const dil3Priv = new Uint8Array(rawBytes.slice(32, 4032));
      const dil3Sig  = Array.from(Dilithium3.sign(msgBytes, dil3Priv)); // 3293B

      // Concatenate: ed25519_sig(64B) || dil3_sig(3293B) = 3357B
      return bytesToHex([...edSig, ...dil3Sig]);
    }

    default:
      throw new Error(`Unsupported key type: ${type}`);
  }
};

/**
 * Verify a signature.
 *
 * @param  {String|Uint8Array} message
 * @param  {String} sig    hex-encoded signature
 * @param  {String} encPublicKey
 * @return {Boolean}
 */
signature.verify = (message, sig, encPublicKey) => {
  if (!message || !sig || !encPublicKey) {
    throw new Error('require message or signature or encPublicKey.');
  }
  const { type, rawBytes } = KeyPair.parsePublicKey(encPublicKey);

  switch (type) {
    case SIGN_TYPE.ed25519: {
      const sigBytes = sjcl.codec.bytes.fromBits(sjcl.codec.hex.toBits(sig));
      return nacl.sign.detached.verify(message, sigBytes, rawBytes);
    }

    case SIGN_TYPE.sm2: {
      // { hash: true, der: false } must match the settings used during signing
      const pubHex = bytesToHex(rawBytes);
      return sm2.doVerifySignature(message, sig, pubHex, { hash: true, der: false });
    }

    case SIGN_TYPE.dilithium3: {
      const sigBytes = new Uint8Array(hexToBytes(sig));
      const pubKey   = new Uint8Array(rawBytes);
      return Dilithium3.verify(sigBytes, msgToBytes(message), pubKey);
    }

    case SIGN_TYPE.hybrid: {
      const sigBytes = hexToBytes(sig);
      const msgBytes = msgToBytes(message);

      // Split public key: ed25519_pub(32B) || dil3_pub(1952B)
      const edPub   = new Uint8Array(rawBytes.slice(0, 32));
      const dil3Pub = new Uint8Array(rawBytes.slice(32, 1984));

      // Split signature: ed25519_sig(64B) || dil3_sig(3293B)
      const edSig   = new Uint8Array(sigBytes.slice(0, 64));
      const dil3Sig = new Uint8Array(sigBytes.slice(64));

      // Both must pass independently
      const edValid   = nacl.sign.detached.verify(msgBytes, edSig, edPub);
      const dil3Valid = Dilithium3.verify(dil3Sig, msgBytes, dil3Pub);
      return edValid && dil3Valid;
    }

    default:
      throw new Error(`Unsupported key type: ${type}`);
  }
};

module.exports = signature;
