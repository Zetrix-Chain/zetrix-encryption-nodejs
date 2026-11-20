'use strict';

// Reproduces the dynamic proof from the SM2 signing-nonce RNG fix: pin Math.random and
// Date identically in two separate process invocations before any signing code
// runs, then sign the same message with the same pre-generated key. If the SM2
// signing nonce is traceable back to Math.random() (instead of a CSPRNG), both
// invocations yield the same signature, which leaks the private key via the
// standard ECDSA/SM2 nonce-reuse formula d = (k-s)(s+r)^-1 mod n.

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

const signature = require('../../lib/signature');

const encPrivateKey = process.argv[2];
const message = process.argv[3];

const sig = signature.sign(message, encPrivateKey);
process.stdout.write(JSON.stringify({ sig }));
