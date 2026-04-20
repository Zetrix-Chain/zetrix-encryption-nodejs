'use strict';

const nacl = require('./vendor/nacl');
const sjcl = require('./vendor/sjcl');
const { sm2, sm3 } = require('sm-crypto');
// ML-DSA-65 (FIPS 204) variant: CRHBYTES=64, sk=4032B, pk=1952B, sig=3309B.
// Used for key generation so that exported private keys are already FIPS 204 format.
const {
  DilithiumLevel,
  DilithiumKeyPair,
  DilithiumPrivateKey,
  DilithiumPublicKey,
  DilithiumSignature,
} = require('./vendor/dilithium3-fips204/index');

const DIL3_LEVEL    = DilithiumLevel.get(3);
const DIL3_PRIV_LEN = DIL3_LEVEL.spec.privateKeyLength;  // 4032
const DIL3_PUB_LEN  = DIL3_LEVEL.spec.publicKeyLength;   // 1952
const DIL3_SIG_LEN  = DIL3_LEVEL.spec.signatureLength;   // 3309
const {
  SIGN_TYPE,
  SIGN_TO_ADDR,
  VALID_SIGN_TYPES,
  VALID_ADDR_TYPES,
} = require('./constants');

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

const sha256 = (bytes) =>
  sjcl.codec.bytes.fromBits(
    sjcl.hash.sha256.hash(sjcl.codec.bytes.toBits(bytes)),
  );

// SM3 hash — accepts plain byte array, returns plain byte array
const sm3Hash = (bytes) => {
  const hexResult = sm3(bytes);
  return hexToBytes(hexResult);
};

const hexToBytes = (hex) => {
  const out = [];
  for (let i = 0; i < hex.length; i += 2) {
    out.push(parseInt(hex.substring(i, i + 2), 16));
  }
  return out;
};

const bytesToHex = (bytes) =>
  bytes.map(b => b.toString(16).padStart(2, '0')).join('');

// Double-hash checksum dispatcher
// typeByte 0x02 (SM2 sign type) and address type 0x02 (SM2 address) both use SM3
const calcHash = (typeByte, data) => {
  if (typeByte === SIGN_TYPE.sm2) {
    return sm3Hash(sm3Hash(data));
  }
  return sha256(sha256(data));
};

// Single public-key hash used for address derivation
const hashPubKey = (signTypeByte, rawPub) => {
  if (signTypeByte === SIGN_TYPE.sm2) {
    return sm3Hash(rawPub);
  }
  return sha256(rawPub);
};

// Convert a message value to a char-code byte array consistent with nacl behavior
const msgToBytes = (msg) => {
  if (typeof msg === 'string') {
    return Uint8Array.from(msg.split('').map(c => c.charCodeAt(0)));
  }
  return msg instanceof Uint8Array ? msg : new Uint8Array(msg);
};

// ---------------------------------------------------------------------------
// KeyPair class
// ---------------------------------------------------------------------------

class KeyPair {
  /**
   * @param {string} signType  'ed25519' | 'sm2' | 'dilithium3' | 'hybrid'  (default 'ed25519')
   */
  constructor(signType = 'ed25519') {
    this.signType = signType;
    this.typeCode = SIGN_TYPE[signType];
    if (this.typeCode === undefined) {
      throw new Error(`Unsupported signType: ${signType}`);
    }
    this.addrTypeByte = SIGN_TO_ADDR[this.typeCode];
    this.rawPub = [];
    this.rawPriv = [];
    this.generate();
  }

  // ---- Key generation ----

  generate() {
    switch (this.signType) {
      case 'ed25519': {
        const srcKP = nacl.sign.keyPair();
        const seed = srcKP.publicKey;            // 32B random seed
        const kp = nacl.sign.keyPair.fromSeed(seed);
        this.rawPriv = Array.from(seed);         // 32B
        this.rawPub  = Array.from(kp.publicKey); // 32B
        break;
      }

      case 'sm2': {
        const kp = sm2.generateKeyPairHex();
        // privateKey: 64-char hex (32B), publicKey: 130-char hex (04||x||y, 65B)
        this.rawPriv = hexToBytes(kp.privateKey.padStart(64, '0')); // 32B
        this.rawPub  = hexToBytes(kp.publicKey);                    // 65B
        break;
      }

      case 'dilithium3': {
        const kp = DilithiumKeyPair.generate(DIL3_LEVEL);
        // Store dil3_priv(DIL3_PRIV_LEN) || dil3_pub(DIL3_PUB_LEN) so pubkey can be
        // reconstructed without re-derivation (matches blockchain KEYDATA layout)
        this.rawPriv = [...Array.from(kp.secret.bytes), ...Array.from(kp.pub.bytes)];
        this.rawPub  = Array.from(kp.pub.bytes); // DIL3_PUB_LEN bytes
        break;
      }

      case 'hybrid': {
        // ED25519 part
        const edSrc  = nacl.sign.keyPair();
        const edSeed = edSrc.publicKey;                          // 32B seed
        const edKP   = nacl.sign.keyPair.fromSeed(edSeed);
        const edPub  = Array.from(edKP.publicKey);               // 32B

        // Dilithium3 part
        const dil3KP   = DilithiumKeyPair.generate(DIL3_LEVEL);
        const dil3Priv = Array.from(dil3KP.secret.bytes);        // DIL3_PRIV_LEN bytes
        const dil3Pub  = Array.from(dil3KP.pub.bytes);           // DIL3_PUB_LEN bytes

        // rawPriv = ed25519_seed(32) || dil3_priv(DIL3_PRIV_LEN) || dil3_pub(DIL3_PUB_LEN)
        this.rawPriv = [...Array.from(edSeed), ...dil3Priv, ...dil3Pub];
        // rawPub  = ed25519_pub(32) || dil3_pub(DIL3_PUB_LEN)
        this.rawPub  = [...edPub, ...dil3Pub];
        break;
      }

      default:
        throw new Error(`Unsupported signType: ${this.signType}`);
    }
  }

  // ---- Instance encoding ----

  getEncPrivateKey() {
    if (!this.rawPriv.length) throw new Error('require rawPriv');
    const nvec = [0xda, 0x37, 0x9f, this.typeCode, ...this.rawPriv, 0x00];
    const checksum = calcHash(this.typeCode, nvec).slice(0, 4);
    return sjcl.codec.base58.encode([...nvec, ...checksum]);
  }

  getEncPublicKey() {
    if (!this.rawPub.length) throw new Error('require rawPub');
    const nvec = [0xb0, this.typeCode, ...this.rawPub];
    const checksum = calcHash(this.typeCode, nvec).slice(0, 4);
    const result = [...nvec, ...checksum];
    return sjcl.codec.hex.fromBits(sjcl.codec.bytes.toBits(result));
  }

  getAddress() {
    if (!this.rawPub.length) throw new Error('require rawPub');
    const head   = [0xF0, 0x26, this.addrTypeByte];
    const hash   = hashPubKey(this.typeCode, this.rawPub).slice(12); // last 20B of pubkey hash
    const buffer = [...head, ...hash];
    // For checksum: dispatch by address type byte (SM2 addr=0x02 uses SM3)
    const checksum = calcHash(this.addrTypeByte, buffer).slice(0, 4);
    return sjcl.codec.base58.encode([...buffer, ...checksum]);
  }

  // ---- Static: public key derivation from encoded private key ----

  static getEncPublicKey(encPrivateKey) {
    if (!encPrivateKey) throw new Error('require the encPrivateKey');
    const { type, rawBytes } = KeyPair.parsePrivateKey(encPrivateKey);
    let rawPub;

    switch (type) {
      case SIGN_TYPE.ed25519: {
        rawPub = Array.from(nacl.sign.keyPair.fromSeed(new Uint8Array(rawBytes)).publicKey);
        break;
      }
      case SIGN_TYPE.sm2: {
        // Derive SM2 public key from private scalar using sm-crypto
        const pubHex = sm2.getPublicKeyFromPrivateKey(bytesToHex(rawBytes));
        rawPub = hexToBytes(pubHex);
        break;
      }
      case SIGN_TYPE.dilithium3: {
        // rawBytes = dil3_priv(4032B, FIPS 204) || dil3_pub(1952B); public key is the last DIL3_PUB_LEN bytes.
        rawPub = rawBytes.slice(rawBytes.length - DIL3_PUB_LEN);
        break;
      }
      case SIGN_TYPE.hybrid: {
        // rawBytes = ed25519_seed(32) || dil3_priv(4032B, FIPS 204) || dil3_pub(1952B)
        // dil3_pub is always the last DIL3_PUB_LEN bytes; ed25519_pub is re-derived from seed.
        const edPub   = Array.from(nacl.sign.keyPair.fromSeed(new Uint8Array(rawBytes.slice(0, 32))).publicKey);
        const dil3Pub = rawBytes.slice(rawBytes.length - DIL3_PUB_LEN);
        rawPub = [...edPub, ...dil3Pub];
        break;
      }
      default:
        throw new Error(`Unsupported key type: ${type}`);
    }

    const nvec = [0xb0, type, ...rawPub];
    const checksum = calcHash(type, nvec).slice(0, 4);
    const result = [...nvec, ...checksum];
    return sjcl.codec.hex.fromBits(sjcl.codec.bytes.toBits(result));
  }

  // ---- Static: address derivation from encoded public key ----

  static getAddress(encPublicKey) {
    if (!encPublicKey) throw new Error('require encPublicKey');
    const { type, rawBytes } = KeyPair.parsePublicKey(encPublicKey);
    const addrTypeByte = SIGN_TO_ADDR[type];
    const head   = [0xF0, 0x26, addrTypeByte];
    const hash   = hashPubKey(type, rawBytes).slice(12);
    const buffer = [...head, ...hash];
    const checksum = calcHash(addrTypeByte, buffer).slice(0, 4);
    return sjcl.codec.base58.encode([...buffer, ...checksum]);
  }

  // ---- Static: parse (decode + validate) ----

  /**
   * Parse and validate an encoded private key.
   * @returns {{ type: number, rawBytes: number[] }}
   */
  static parsePrivateKey(encPrivateKey) {
    const bits = sjcl.codec.base58.decode(encPrivateKey);

    if (bits[0] !== 0xda || bits[1] !== 0x37 || bits[2] !== 0x9f) {
      throw new Error(`private key ${encPrivateKey} is invalid, header is wrong`);
    }
    const type = bits[3];
    if (!VALID_SIGN_TYPES.includes(type)) {
      throw new Error(`private key ${encPrivateKey} is invalid, type is wrong`);
    }

    const len = bits.length;
    if (bits[len - 5] !== 0x00) {
      throw new Error(`private key ${encPrivateKey} is invalid, compression bit is wrong`);
    }

    const withoutChecksum = bits.slice(0, len - 4);
    const storedHash      = bits.slice(len - 4, len);
    const calcHashResult  = calcHash(type, withoutChecksum).slice(0, 4);
    if (storedHash.join() !== calcHashResult.join()) {
      throw new Error(`private key ${encPrivateKey} is invalid, hash is wrong`);
    }

    return { type, rawBytes: bits.slice(4, len - 5) };
  }

  /**
   * Parse and validate an encoded public key.
   * @returns {{ type: number, rawBytes: number[] }}
   */
  static parsePublicKey(encPublicKey) {
    const bytes = sjcl.codec.bytes.fromBits(sjcl.codec.hex.toBits(encPublicKey));

    if (bytes[0] !== 0xb0) {
      throw new Error(`public key ${encPublicKey} is invalid, header is wrong`);
    }
    const type = bytes[1];
    if (!VALID_SIGN_TYPES.includes(type)) {
      throw new Error(`public key ${encPublicKey} is invalid, type is wrong`);
    }

    const len             = bytes.length;
    const withoutChecksum = bytes.slice(0, len - 4);
    const storedHash      = bytes.slice(len - 4, len);
    const calcHashResult  = calcHash(type, withoutChecksum).slice(0, 4);
    if (storedHash.join() !== calcHashResult.join()) {
      throw new Error(`public key ${encPublicKey} is invalid, hash is wrong`);
    }

    return { type, rawBytes: bytes.slice(2, len - 4) };
  }

  // ---- Static: generate keypair ----

  static getKeyPair(signType = 'ed25519') {
    const kp = new KeyPair(signType);
    return {
      encPrivateKey: kp.getEncPrivateKey(),
      encPublicKey:  kp.getEncPublicKey(),
      address:       kp.getAddress(),
      signType,
    };
  }

  // ---- Static: validation ----

  static checkEncPrivateKey(encPrivateKey) {
    try {
      if (!encPrivateKey || typeof encPrivateKey !== 'string') return false;
      const bits = sjcl.codec.base58.decode(encPrivateKey.trim());
      if (bits[0] !== 0xda || bits[1] !== 0x37 || bits[2] !== 0x9f) return false;
      const type = bits[3];
      if (!VALID_SIGN_TYPES.includes(type)) return false;
      const len = bits.length;
      if (bits[len - 5] !== 0x00) return false;
      const withoutChecksum = bits.slice(0, len - 4);
      const storedHash      = bits.slice(len - 4, len);
      const calResult       = calcHash(type, withoutChecksum).slice(0, 4);
      return storedHash.join() === calResult.join();
    } catch (_) {
      return false;
    }
  }

  static checkEncPublicKey(encPublicKey) {
    try {
      if (!encPublicKey || typeof encPublicKey !== 'string') return false;
      const bytes = sjcl.codec.bytes.fromBits(sjcl.codec.hex.toBits(encPublicKey.trim()));
      if (bytes[0] !== 0xb0) return false;
      const type = bytes[1];
      if (!VALID_SIGN_TYPES.includes(type)) return false;
      const len             = bytes.length;
      const withoutChecksum = bytes.slice(0, len - 4);
      const storedHash      = bytes.slice(len - 4, len);
      const calResult       = calcHash(type, withoutChecksum).slice(0, 4);
      return storedHash.join() === calResult.join();
    } catch (_) {
      return false;
    }
  }

  static checkAddress(address) {
    try {
      if (!address || typeof address !== 'string') return false;
      const arr = sjcl.codec.base58.decode(address.trim());
      if (!Array.isArray(arr) || arr[0] !== 0xF0 || arr[1] !== 0x26) return false;
      const addrTypeByte = arr[2];
      if (!VALID_ADDR_TYPES.includes(addrTypeByte)) return false;
      if (arr.length !== 27) return false;
      const withoutChecksum = arr.slice(0, arr.length - 4);
      const storedHash      = arr.slice(arr.length - 4, arr.length);
      // Dispatch by address type byte: SM2 (0x02) uses SM3; others use SHA-256
      const calResult = calcHash(addrTypeByte, withoutChecksum).slice(0, 4);
      return storedHash.join() === calResult.join();
    } catch (_) {
      return false;
    }
  }
}

module.exports = KeyPair;
