'use strict';

const nacl = require('./vendor/nacl');
const sjcl = require('./vendor/sjcl');
const { sm2 } = require('sm-crypto');
// ML-DSA-65 (FIPS 204) variant: CRHBYTES=64, c_tilde=48B, sig=3309B
const {
  DilithiumLevel: Dil3LevelFips,
  DilithiumPrivateKey: Dil3PrivKeyFips,
  DilithiumPublicKey: Dil3PubKeyFips,
  DilithiumSignature: Dil3SigFips,
} = require('./vendor/dilithium3-fips204/index');
const DIL3_FIPS_LEVEL = Dil3LevelFips.get(3);

const DIL3_PUB_LEN = DIL3_FIPS_LEVEL.spec.publicKeyLength;  // 1952

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
      const privHex = bytesToHex(rawBytes);
      return sm2.doSignature(message, privHex, { hash: true, der: false });
    }

    case SIGN_TYPE.dilithium3: {
      // rawBytes = dil3_priv(4032B) || dil3_pub(1952B)
      const dil3PrivBytes = new Uint8Array(rawBytes.slice(0, rawBytes.length - DIL3_PUB_LEN));
      const privKey = Dil3PrivKeyFips.fromBytes(dil3PrivBytes, DIL3_FIPS_LEVEL);
      const sig = Dil3SigFips.generate(msgToBytes(message), privKey);
      return bytesToHex(sig.bytes);
    }

    case SIGN_TYPE.hybrid: {
      // rawBytes = ed25519_seed(32B) || dil3_priv(4032B) || dil3_pub(1952B)
      const msgBytes = msgToBytes(message);

      // ED25519 sign
      const edKP  = nacl.sign.keyPair.fromSeed(new Uint8Array(rawBytes.slice(0, 32)));
      const edSig = Array.from(nacl.sign.detached(msgBytes, edKP.secretKey)); // 64B

      // Dilithium3 sign (ML-DSA-65)
      const dil3PrivBytes = new Uint8Array(rawBytes.slice(32, rawBytes.length - DIL3_PUB_LEN));
      const dil3Priv = Dil3PrivKeyFips.fromBytes(dil3PrivBytes, DIL3_FIPS_LEVEL);
      const dil3Sig = Array.from(Dil3SigFips.generate(msgBytes, dil3Priv).bytes); // 3309B

      // Concatenate: ed25519_sig(64B) || dil3_sig(3309B) = 3373B
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
      const pubHex = bytesToHex(rawBytes);
      return sm2.doVerifySignature(message, sig, pubHex, { hash: true, der: false });
    }

    case SIGN_TYPE.dilithium3: {
      // rawBytes = dil3_pub(1952B)
      const pubKey = Dil3PubKeyFips.fromBytes(new Uint8Array(rawBytes), DIL3_FIPS_LEVEL);
      const sigObj = Dil3SigFips.fromBytes(new Uint8Array(hexToBytes(sig)), DIL3_FIPS_LEVEL);
      return sigObj.verify(msgToBytes(message), pubKey);
    }

    case SIGN_TYPE.hybrid: {
      const sigBytes = hexToBytes(sig);
      const msgBytes = msgToBytes(message);

      // Split public key: ed25519_pub(32B) || dil3_pub(1952B)
      const edPub   = new Uint8Array(rawBytes.slice(0, 32));
      const dil3Pub = Dil3PubKeyFips.fromBytes(new Uint8Array(rawBytes.slice(32, 32 + DIL3_PUB_LEN)), DIL3_FIPS_LEVEL);

      // Split signature: ed25519_sig(64B) || dil3_sig(3309B)
      const edSig   = new Uint8Array(sigBytes.slice(0, 64));
      const dil3Sig = Dil3SigFips.fromBytes(new Uint8Array(sigBytes.slice(64)), DIL3_FIPS_LEVEL);

      // Both must pass independently
      const edValid   = nacl.sign.detached.verify(msgBytes, edSig, edPub);
      const dil3Valid = dil3Sig.verify(msgBytes, dil3Pub);
      return edValid && dil3Valid;
    }

    default:
      throw new Error(`Unsupported key type: ${type}`);
  }
};

module.exports = signature;
