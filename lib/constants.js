'use strict';

// Sign type byte embedded in encoded private/public keys
const SIGN_TYPE = {
  ed25519:    0x01,
  sm2:        0x02,
  // 0x04 (CFCA) is a dead slot — never used
  dilithium3: 0x05,
  hybrid:     0x06,
};

// Address byte embedded in encoded addresses
// NOTE: Dilithium3 has a mismatch — signType=0x05 but address byte=0x04 (intentional, for stable ZTX4 prefix)
const ADDRESS_TYPE = {
  ed25519:    0x01,  // -> ZTX3
  sm2:        0x02,  // -> ZTX3
  dilithium3: 0x04,  // -> ZTX4  (NOT 0x05)
  hybrid:     0x06,  // -> ZTX5
};

// Maps sign type byte -> address byte
const SIGN_TO_ADDR = {
  0x01: 0x01,
  0x02: 0x02,
  0x05: 0x04,  // dilithium3: sign=0x05 -> addr=0x04
  0x06: 0x06,
};

// Valid sign type bytes for private/public key validation
const VALID_SIGN_TYPES = [0x01, 0x02, 0x05, 0x06];

// Valid address bytes for address validation
// Note: 0x04 is a valid ADDRESS byte (dilithium3) even though 0x04 is a dead SIGN type (CFCA)
const VALID_ADDR_TYPES = [0x01, 0x02, 0x04, 0x06];

module.exports = {
  SIGN_TYPE,
  ADDRESS_TYPE,
  SIGN_TO_ADDR,
  VALID_SIGN_TYPES,
  VALID_ADDR_TYPES,
};
