'use strict';

// Disallows passing a secret-shaped value to console.* or to an Error
// constructor's message, anywhere in lib/ (see eslint.config.js for the
// lib/vendor/ exclusion). Walks the full argument AST recursively instead of
// matching source text line-by-line, so it isn't fooled by template-literal
// interpolation, string concatenation, JSON.stringify(x), bracket-notation
// console['log'](...), object-shorthand ({ privateKey }), or member access
// (salt.join(), err.privateKey = x). Also tracks, within a single file in
// one top-to-bottom pass (no cross-function/import scope analysis): which
// local variables hold an Error-like object (so `x.k = secret; throw x;`
// is caught however `x` is named or declared -- a catch parameter, or
// assigned from `new SomeError(...)`), and which local variables alias the
// `console` object or one of its logging methods (`const { log } = console`,
// `const log = console.log`, `const c = console`).
//
// This is accepted as best-effort defence in depth, not a complete static
// guarantee -- no lint rule can be. Below is the full known-gap list, kept
// here AND in README.md so it travels with the rule. Deliberately not
// chased further:
//   - The rule inspects the literal AST at the call/throw site only -- it
//     does not trace a secret's value backward through an intervening
//     local variable (`const s = privateKey; console.log(s)`, `const msg =
//     'bad ' + privateKey; throw new Error(msg)`).
//   - A secret thrown as a bare string/template/String() call rather than
//     an Error instance is not checked: `throw 'bad ' + privateKey`,
//     `` throw `bad ${privateKey}` ``, `throw String(privateKey)`.
//   - Only three sinks are checked at all: `console.*`, `process.stdout/
//     stderr.write`, and Error-like constructors. A generic logger object
//     (`logger.info(iv)`), the `debug` package (`require('debug')('x')
//     (privateKey)`), `process.emitWarning(...)`, and `assert()`/
//     `assert.ok()` messages are not checked. (Not used anywhere in lib/
//     today -- if one of these is introduced later, it needs either a
//     rule update or a manual review.)
//   - Secret-shaped names outside the pattern below: short/generic ones
//     like `k`, `sk`, `kp`, `aesKey`, `derivedKey` were deliberately left
//     out -- a pattern broad enough to catch them (e.g. bare `k`) matches
//     too many unrelated identifiers (loop counters, etc.) across lib/ to
//     be usable without a flood of false positives.
//   - console/method aliasing created by a plain assignment rather than a
//     declaration (`let l; l = console.log; l(iv)`, `let c; c = console;
//     c.log(iv)`), an assignment-expression destructure (`({ log } =
//     console)`), `.bind(...)` (`console.log.bind(console)`), a plain
//     declaration alias of `process.stdout` (`const out = process.stdout;
//     out.write(iv)`), default/rest destructuring of `console` (`const
//     { log = null } = console`, `const { ...c } = console`), or a
//     destructure one level removed from `console`/`process` (`const
//     { stdout } = process`, `const { console: c } = globalThis`).
//   - LOGGING_METHODS covers log/error/warn/info/debug/trace/dir/table but
//     not `console.assert`, `console.group`/`groupCollapsed`, `dirxml`,
//     `timeLog`, or `count` -- all of which print their arguments too.
//   - An Error-like holder not recognised as such: `Reflect.set`/
//     `Reflect.defineProperty`/`Object.defineProperties` on a holder, a
//     secret passed directly in the constructor message of an Error
//     subclass whose name doesn't end in "Error" (`new BadKey(privateKey)`,
//     `super(privateKey)` -- distinct from the already-covered case of
//     attaching a secret as a property on a tracked holder), an alias of
//     an already-tracked holder (`const r = q; r.k = secret;`), or a
//     nested path (`this.err.k = secret`, `q.data.k = secret`).
//   - Logging reached through `.call()`/`.apply()`/`Reflect.apply`, a
//     computed `process['stdout']`, or `require('process').stdout`.
//   - A secret thrown as a bare object literal (`throw { message: x }`)
//     rather than an Error instance, passed to an arbitrary callback
//     (`cb(privateKey)`) that might itself log it, passed through
//     `Promise.reject({...})`, passed as an extra argument to a function
//     that itself logs it (`run(log, iv)`), or built by an opaque helper
//     before being thrown (`throw mk(privateKey);`).
//   - Object.defineProperty/assign targets that aren't literally `Object.*`
//     (e.g. a local alias of `Object`).
//
// See test/keystore-keypair-hardening.test.js's assertNoLeak() for the
// equivalent runtime-side check: it captures only five console methods
// (log/error/warn/info/debug) around keystore.js's encrypt/decrypt/
// decrypt1 and inspects thrown errors with util.inspect(err, { showHidden:
// true }) -- so it too sees a secret attached as a non-enumerable property,
// the same as this rule's own Object.defineProperty check above (which
// flags the value argument regardless of the descriptor's `enumerable`
// setting) -- but it does not cover lib/keypair.js or lib/signature.js at
// all, and does not capture console.assert/count/group or
// process.stdout/stderr.write either.

// Exact names that don't fit the generic pattern below (e.g. "rawBytes" has
// no secret-shaped substring of its own).
const SECRET_NAMES = new Set([
  'encrypted', 'ciphertext', 'cypher_text', 'respdata', 'rawbytes',
].map((n) => n.toLowerCase()));

// Generic pattern covering the secret-shaped names actually used across lib/
// (privateKey/encPrivateKey/privHex/privKey, secretKey, seed/edSeed/
// secureSeedHex, salt, iv, dk/key, mnemonic, password/passwd) rather than an
// exhaustive exact-name list, so a new variable following the same naming
// convention is covered without updating this rule again.
const SECRET_NAME_PATTERN = /priv|secret|seed|salt|^iv$|^dk$|^key$|mnemonic|pass/i;

const LOGGING_METHODS = new Set(['log', 'error', 'warn', 'info', 'debug', 'trace', 'dir', 'table']);

function isSecretName(name) {
  if (typeof name !== 'string') return false;
  return SECRET_NAMES.has(name.toLowerCase()) || SECRET_NAME_PATTERN.test(name);
}

function containsSecretIdentifier(node, seen) {
  if (!node || typeof node !== 'object' || seen.has(node)) return false;
  seen.add(node);

  if (node.type === 'Identifier' && isSecretName(node.name)) return true;
  if (node.type === 'Property' && node.key && node.key.type === 'Identifier' && isSecretName(node.key.name)) {
    // Covers both shorthand ({ privateKey }) and explicit ({ privateKey: x })
    return true;
  }
  if (node.type === 'MemberExpression') {
    // `.length` never exposes content (e.g. `rawBytes.length` in a "wrong
    // key length" message) -- don't flag it and don't recurse into it, or
    // every length check on a secret-named array would be flagged too.
    if (!node.computed && node.property && node.property.type === 'Identifier' && node.property.name === 'length') {
      return false;
    }
    if (!node.computed && node.property && node.property.type === 'Identifier' && isSecretName(node.property.name)) {
      return true;
    }
    if (node.computed && node.property && node.property.type === 'Literal' && isSecretName(node.property.value)) {
      return true;
    }
    // Also flags member access ON a secret-named base (e.g. salt.join()),
    // via the generic recursion below walking into `object`.
  }

  for (const key of Object.keys(node)) {
    if (key === 'parent' || key === 'loc' || key === 'range') continue;
    const value = node[key];
    if (Array.isArray(value)) {
      for (const item of value) {
        if (item && typeof item.type === 'string' && containsSecretIdentifier(item, seen)) return true;
      }
    } else if (value && typeof value.type === 'string') {
      if (containsSecretIdentifier(value, seen)) return true;
    }
  }
  return false;
}

function getCalleeName(node) {
  if (node.type === 'Identifier') return node.name;
  // Error-like constructor/factory reached through a member expression,
  // e.g. `new errors.KeyError(...)` or `lib.SomeError(...)`.
  if (node.type === 'MemberExpression' && !node.computed && node.property.type === 'Identifier') {
    return node.property.name;
  }
  return null;
}

// True for `console` itself, or anything ending in `.console`
// (globalThis.console, window.console). `aliasNames` additionally tracks
// local identifiers the whole `console` object was assigned to
// (`const c = console;`).
function isConsoleExpression(node, aliasNames) {
  if (!node) return false;
  if (node.type === 'Identifier' && (node.name === 'console' || aliasNames.has(node.name))) return true;
  if (node.type === 'MemberExpression' && !node.computed && node.property.type === 'Identifier') {
    return node.property.name === 'console';
  }
  return false;
}

// True for `process.stdout.write` / `process.stderr.write`.
function isProcessStreamWrite(callee) {
  if (callee.type !== 'MemberExpression' || callee.computed) return false;
  if (!callee.property || callee.property.name !== 'write') return false;
  const obj = callee.object;
  if (obj.type !== 'MemberExpression' || obj.computed) return false;
  if (!obj.property || (obj.property.name !== 'stdout' && obj.property.name !== 'stderr')) return false;
  return obj.object && obj.object.type === 'Identifier' && obj.object.name === 'process';
}

function isObjectMethodCall(callee, methodName) {
  return callee.object.type === 'Identifier' && callee.object.name === 'Object' &&
    !callee.computed && callee.property.type === 'Identifier' && callee.property.name === methodName;
}

// True when `node` is a construction of something Error-like
// (`new XError(...)` or `XError(...)` without `new`).
function isErrorLikeConstruction(node) {
  if (!node || (node.type !== 'NewExpression' && node.type !== 'CallExpression')) return false;
  const calleeName = getCalleeName(node.callee);
  return !!calleeName && /Error$/.test(calleeName);
}

module.exports = {
  meta: {
    type: 'problem',
    docs: {
      description: 'Disallow passing secret-shaped values to console.* or Error constructors',
    },
    schema: [],
  },
  create(context) {
    // Per-file state, populated top-to-bottom as the AST is walked (no
    // cross-scope/import analysis -- a declaration must appear before its
    // use in source order, which is the normal, overwhelmingly common case).
    const errorHolderNames = new Set(); // vars known to hold an Error-like object
    const consoleAliasNames = new Set(); // vars aliasing the whole `console` object
    const consoleMethodAliasNames = new Set(); // vars bound to a single logging method

    function check(node, args) {
      for (const arg of args) {
        if (containsSecretIdentifier(arg, new Set())) {
          context.report({
            node,
            message: 'Possible secret-shaped value passed here -- do not log or embed key/salt/iv/password material.',
          });
          return;
        }
      }
    }

    function checkErrorLikeCall(node) {
      if (isErrorLikeConstruction(node)) check(node, node.arguments);
    }

    return {
      CatchClause(node) {
        if (node.param && node.param.type === 'Identifier') {
          errorHolderNames.add(node.param.name);
        }
      },

      VariableDeclarator(node) {
        if (node.id.type === 'Identifier' && isErrorLikeConstruction(node.init)) {
          errorHolderNames.add(node.id.name);
          return;
        }
        if (!node.init) return;
        if (node.id.type === 'Identifier' && isConsoleExpression(node.init, consoleAliasNames)) {
          // const c = console;
          consoleAliasNames.add(node.id.name);
          return;
        }
        if (
          node.id.type === 'Identifier' && node.init.type === 'MemberExpression' &&
          isConsoleExpression(node.init.object, consoleAliasNames) &&
          !node.init.computed && node.init.property.type === 'Identifier' &&
          LOGGING_METHODS.has(node.init.property.name)
        ) {
          // const log = console.log;
          consoleMethodAliasNames.add(node.id.name);
          return;
        }
        if (
          node.id.type === 'ObjectPattern' && isConsoleExpression(node.init, consoleAliasNames)
        ) {
          // const { log } = console; (including a rename: const { log: myLog } = console;)
          for (const prop of node.id.properties) {
            if (
              prop.type === 'Property' && !prop.computed &&
              prop.key.type === 'Identifier' && LOGGING_METHODS.has(prop.key.name) &&
              prop.value.type === 'Identifier'
            ) {
              consoleMethodAliasNames.add(prop.value.name);
            }
          }
        }
      },

      CallExpression(node) {
        const callee = node.callee;

        if (callee.type === 'Identifier' && consoleMethodAliasNames.has(callee.name)) {
          // log(iv) where `log` is a local alias for a console method
          check(node, node.arguments);
        }

        if (callee.type === 'MemberExpression') {
          if (isConsoleExpression(callee.object, consoleAliasNames)) {
            let methodName = null;
            if (!callee.computed && callee.property.type === 'Identifier') {
              methodName = callee.property.name;
            } else if (callee.computed && callee.property.type === 'Literal') {
              methodName = callee.property.value;
            }
            if (methodName && LOGGING_METHODS.has(methodName)) {
              check(node, node.arguments);
            }
          } else if (isProcessStreamWrite(callee)) {
            check(node, node.arguments);
          } else if (isObjectMethodCall(callee, 'assign') || isObjectMethodCall(callee, 'defineProperty')) {
            // Object.assign(target, { secret }) / Object.defineProperty(target,
            // 'k', { value: secret }) -- both commonly used to attach extra
            // data (e.g. a secret) onto an object such as an Error before
            // it's thrown or logged.
            check(node, node.arguments);
          }
        }

        // throw Error(...) without `new`, or an Error-like call reached
        // through a member expression (lib.SomeError(...))
        checkErrorLikeCall(node);
      },

      NewExpression(node) {
        checkErrorLikeCall(node);
      },

      // Attaching a secret-shaped value onto an exception object before
      // throwing/logging it (e.g. `e.privateKey = privateKey; throw e;`) is
      // just as dangerous as logging it directly. Fires when the assignment
      // target is a variable known to hold an Error-like object (tracked
      // above: a catch parameter, or assigned from `new SomeError(...)`
      // either at declaration or by plain reassignment here), OR when it
      // merely looks like one by common naming convention (covers the
      // simple, undeclared case in an isolated snippet/test). Deliberately
      // does NOT fire for arbitrary object/`this` property assignment --
      // this codebase's constructors legitimately store secret-shaped
      // values as plain properties (e.g. KeyPair#rawPriv, a separate
      // pre-existing/out-of-scope issue), and a broader rule here would
      // flag every one of them.
      AssignmentExpression(node) {
        if (node.left.type === 'Identifier') {
          // x = new Error(); -- a plain (re)assignment, not a property write
          if (isErrorLikeConstruction(node.right)) errorHolderNames.add(node.left.name);
          return;
        }
        if (node.left.type !== 'MemberExpression') return;
        const target = node.left.object;
        if (target.type !== 'Identifier') return;
        const looksLikeErrorVar = /^(e|err|error|ex|exc|exception)$/i.test(target.name) || errorHolderNames.has(target.name);
        if (!looksLikeErrorVar) return;
        if (containsSecretIdentifier(node.right, new Set())) {
          context.report({
            node,
            message: 'Possible secret-shaped value assigned onto an error-like object here -- do not attach key/salt/iv/password material to an object that may later be logged or thrown.',
          });
        }
      },
    };
  },
};
