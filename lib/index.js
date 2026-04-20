'use strict';

const keypair = require('./keypair');
const signature = require('./signature');
const keystore = require('./keystore');
const { SIGN_TYPE, ADDRESS_TYPE, SIGN_TO_ADDR, VALID_SIGN_TYPES, VALID_ADDR_TYPES } = require('./constants');

const KEY_TYPES = SIGN_TYPE;

module.exports = { keypair, signature, keystore, KEY_TYPES, SIGN_TYPE, ADDRESS_TYPE, SIGN_TO_ADDR, VALID_SIGN_TYPES, VALID_ADDR_TYPES };
