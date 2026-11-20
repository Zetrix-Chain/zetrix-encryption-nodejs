'use strict';

const { RuleTester } = require('eslint');
const rule = require('../eslint-rules/no-secret-logging');

const ruleTester = new RuleTester({
  languageOptions: { ecmaVersion: 2021, sourceType: 'script' },
});

describe('eslint-rules/no-secret-logging', function() {
  it('accepts known-good samples and rejects known-bad samples', function() {
    ruleTester.run('no-secret-logging', rule, {
      valid: [
        // Static strings mentioning a secret-shaped word, no interpolation
        "throw new Error('require password');",
        "throw new Error('require the encPrivateKey');",
        "console.log('encryption complete');",
        // Logging something unrelated
        "console.log(result);",
        "console.error(err.message);",
        // Non-secret member/property names
        "console.log(user.name);",
        "throw new Error('bad ' + user.name);",
        // Assigning a non-secret value onto an unrelated property -- must not false-positive
        "obj.count = count;",
        "e.code = 'E_BAD_INPUT';",
        // .length never exposes content -- must not false-positive (real line in lib/keypair.js)
        "throw new Error(`bad length ${rawBytes.length}`);",
        // Legitimate constructor-style property assignment on a non-error target
        "this.rawPriv = rawPriv;",
        // A non-secret value assigned onto an untracked object -- must not false-positive
        "const result = {}; result.k = 5;",
        // A real Error, but nothing secret ever assigned onto it
        "const e2 = new Error('bad input'); e2.code = 'E_BAD'; throw e2;",
        // A plain object/function alias, not console -- calling it must not false-positive
        "const log = helper.log; log(user.name);",
      ],
      invalid: [
        // Original leaking line: wrapped call, not a bare identifier
        { code: 'console.log(sjcl.codec.hex.toBits(iv));', errors: 1 },
        // Template-literal interpolation (shape of the original private-key leak)
        { code: 'throw new Error(`private key ${encPrivateKey} is invalid`);', errors: 1 },
        // String concatenation
        { code: "console.error('k=' + privateKey);", errors: 1 },
        { code: "throw new Error('bad: ' + encPrivateKey);", errors: 1 },
        // throw Error(...) without `new`
        { code: 'throw Error(`${privateKey}`);', errors: 1 },
        { code: 'throw TypeError(`${privateKey}`);', errors: 1 },
        // Bracket-notation console method
        { code: "console['log'](salt);", errors: 1 },
        // Object shorthand
        { code: 'console.log({ privateKey });', errors: 1 },
        // Member expression on a secret-named base
        { code: 'console.log(salt.join());', errors: 1 },
        // Secret-named property read via member access, interpolated into the message
        { code: 'throw new Error(`code=${err.privateKey}`);', errors: 1 },
        // Multiple console logging methods
        { code: 'console.warn(iv);', errors: 1 },
        { code: 'console.info(encrypted);', errors: 1 },
        { code: 'console.debug(cypher_text);', errors: 1 },
        // Secret names actually used in lib/ beyond the original list
        { code: 'console.log(key);', errors: 1 },
        { code: 'console.log(dk);', errors: 1 },
        { code: 'console.log(seed);', errors: 1 },
        { code: 'console.log(edSeed);', errors: 1 },
        { code: 'console.log(secureSeedHex);', errors: 1 },
        { code: 'console.log(privHex);', errors: 1 },
        { code: 'console.log(privKey);', errors: 1 },
        { code: 'console.log(mnemonic);', errors: 1 },
        { code: 'throw new Error(`bad length ${rawBytes}`);', errors: 1 },
        // A secret VALUE assigned onto any property (e.g. attaching
        // it to an error object before throwing) -- distinct from reading a
        // secret-named property, which the earlier "err.privateKey" case covers.
        { code: 'e.privateKey = privateKey; throw e;', errors: 1 },
        { code: 'Object.assign(new Error("x"), { data: privateKey });', errors: 1 },
        // An Error-like constructor reached through a member expression
        { code: 'throw new errors.KeyError(`${privateKey}`);', errors: 1 },
        // Console methods beyond log/error/warn/info/debug
        { code: 'console.trace(privateKey);', errors: 1 },
        { code: 'console.dir(privateKey);', errors: 1 },
        { code: 'console.table(privateKey);', errors: 1 },
        // Console reached through globalThis
        { code: 'globalThis.console.log(privateKey);', errors: 1 },
        // process.stdout/stderr.write
        { code: 'process.stdout.write(privateKey);', errors: 1 },
        { code: 'process.stderr.write(String(privateKey));', errors: 1 },
        // A secret attached to an error-holding
        // variable under an arbitrary name -- caught by what the variable
        // HOLDS (constructed via *Error(), or a catch param), not by its name.
        { code: 'const e2 = new Error(); e2.k = privateKey; throw e2;', errors: 1 },
        { code: "const failure = new TypeError('bad'); failure.k = privateKey; throw failure;", errors: 1 },
        { code: 'try { f(); } catch (x) { x.k = privateKey; throw x; }', errors: 1 },
        { code: 'let box; box = new Error(); box.k = privateKey; throw box;', errors: 1 },
        // Object.defineProperty as another way to attach data onto an object
        { code: "Object.defineProperty(e, 'k', { value: privateKey });", errors: 1 },
        // Console bound to a local name, either
        // via destructuring or a direct reference, then called through that
        // name -- caught without relying on runtime console capture.
        { code: 'const { log } = console; log(iv);', errors: 1 },
        { code: 'const log = console.log; log(iv);', errors: 1 },
        { code: 'const c = console; c.log(iv);', errors: 1 },
      ],
    });
  });
});
