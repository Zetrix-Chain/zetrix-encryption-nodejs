'use strict';

// Reproduces the dynamic proof from the key-generation RNG fix: pin Math.random and
// Date to identical, attacker-predictable state in two separate process
// invocations before any key-generation code runs, then generate a keypair.
// If the library's key material is traceable back to Math.random()/Date
// (instead of a CSPRNG), both invocations yield the same raw private key.

let state = 0x1234abcd;
Math.random = function seededRandom() {
  state ^= state << 13; state >>>= 0;
  state ^= state >>> 17;
  state ^= state << 5; state >>>= 0;
  return state / 4294967296;
};

const FIXED_EPOCH = 1700000000000;
const RealDate = Date;
function PinnedDate(...args) {
  return args.length ? new RealDate(...args) : new RealDate(FIXED_EPOCH);
}
PinnedDate.now = () => FIXED_EPOCH;
PinnedDate.prototype = RealDate.prototype;
global.Date = PinnedDate;

const KeyPair = require('../../lib/keypair');

const signType = process.argv[2];
const kp = new KeyPair(signType);
process.stdout.write(JSON.stringify({ rawPriv: kp.rawPriv }));
