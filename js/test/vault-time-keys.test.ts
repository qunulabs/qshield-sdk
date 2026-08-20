/**
 * Time-constrained keys: client.vault.timeConstrainedKeys.
 *
 * Four properties here matter more than the route coverage, and every one of
 * them is something an integration would otherwise get quietly and badly wrong.
 *
 * THE THREE REFUSALS ARE THREE DIFFERENT FAILURES. Too early, too late, and a
 * wrong passphrase each have their own class. Collapsing any two would send a
 * caller down the wrong road: a retry loop against a key whose material has
 * already been shredded, or a passphrase hunt for a key that has simply not
 * opened yet. The tests below assert the classes are distinct, not merely that
 * something was thrown.
 *
 * ENCRYPTING AND DECRYPTING ARE GATED DIFFERENTLY, ON PURPOSE. Encrypting is
 * allowed before the window opens; decrypting is not. That asymmetry is the
 * feature, so it is pinned rather than assumed.
 *
 * THE PASSPHRASE APPEARS EXACTLY ONCE, ON CREATE. It is never on a read, never
 * in a URL, and a protected key that arrives without one is a broken response
 * rather than a key with an empty passphrase.
 *
 * BINARY IS BYTES, BOTH WAYS. Base64 is a wire detail and reaches no public type.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { clientWith } from '../src/client.js'
import {
  NotLicensedError,
  NotFoundError,
  ProtocolError,
  TimeKeyExpiredError,
  TimeKeyNotYetValidError,
  TimeKeyPassphraseRejectedError,
  VaultSealedError,
} from '../src/index.js'
import { CREDENTIAL, created, fail, ok, startStub, token, type Stub } from './support/stub.js'

const TOKEN = '/api/v1/auth/token'
const TC = '/api/v1/vault/tc-keys'

function clientFor(stub: Stub) {
  return clientWith({ baseUrl: stub.baseUrl, ...CREDENTIAL }, {})
}

/** Answers the token exchange, and hands everything else to the test. */
function withToken(respond: Parameters<typeof startStub>[0]): Parameters<typeof startStub>[0] {
  return (req, res, index) => {
    if (req.path === TOKEN) return token(res, 'tok-1')
    return respond(req, res, index)
  }
}

/** Every request the stub saw that was not the credential exchange. */
function calls(stub: Stub) {
  return stub.requests.filter((r) => r.path !== TOKEN)
}

/** The body of the first product call, parsed. */
function sentBody(stub: Stub): Record<string, unknown> {
  return JSON.parse(calls(stub)[0]?.body ?? '{}') as Record<string, unknown>
}

const bytes = (...values: number[]) => Uint8Array.from(values)

// Awkward on purpose: a zero byte, a high byte, and a length that does not
// divide by three, so base64 padding is exercised rather than assumed.
const PLAINTEXT = bytes(0, 1, 254, 255, 42)
const CIPHERTEXT = bytes(200, 0, 13)
const LABEL = bytes(1, 2, 3)
const PUBLIC_KEY = bytes(48, 130, 1, 10)
const SECRET = bytes(7, 0, 255)

const PLAINTEXT_B64 = 'AAH+/yo='
const CIPHERTEXT_B64 = 'yAAN'
const LABEL_B64 = 'AQID'
const PUBLIC_KEY_B64 = 'MIIBCg=='
const SECRET_B64 = 'BwD/'

const OPENS = '2026-10-01T00:00:00.000Z'
const CLOSES = '2026-10-08T00:00:00.000Z'

/** A key as qshield reports one. `extra` overrides or adds fields. */
function keyBody(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'b0a1c2d3-0000-0000-0000-000000000001',
    alias: 'quarter-close',
    algorithm_id: 'rsa_3072',
    purpose: 'encryption',
    passphrase_protected: false,
    not_before: OPENS,
    not_after: CLOSES,
    status: 'active',
    window_status: 'pending',
    created_at: '2026-09-01T09:00:00Z',
    updated_at: '2026-09-01T09:00:00Z',
    ...extra,
  }
}

test('listing reads every key, and drops the stored status in favour of the derived one', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, [keyBody(), keyBody({ alias: 'other', window_status: 'active' })])
    }),
  )
  try {
    const keys = await clientFor(stub).vault.timeConstrainedKeys.list()
    assert.equal(keys.length, 2)
    assert.equal(keys[0]?.alias, 'quarter-close')
    assert.equal(keys[0]?.windowStatus, 'pending')
    assert.equal(keys[1]?.windowStatus, 'active')
    assert.deepEqual(keys[0]?.notBefore, new Date(OPENS))
    assert.deepEqual(keys[0]?.notAfter, new Date(CLOSES))
    // The stored status says nothing the derived one does not, and the two
    // disagree for a while after expiry because the sweep runs in the
    // background. Publishing both would only invite a caller to trust the wrong
    // one.
    assert.equal('status' in (keys[0] as object), false)
    assert.equal(calls(stub)[0]?.method, 'GET')
    assert.equal(calls(stub)[0]?.path, TC)
  } finally {
    await stub.close()
  }
})

test('creating an unprotected key sends the window as timestamps and returns no passphrase', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      created(res, { ...keyBody(), public_key: PUBLIC_KEY_B64 })
    }),
  )
  try {
    const key = await clientFor(stub).vault.timeConstrainedKeys.create({
      alias: 'quarter-close',
      algorithmId: 'rsa_3072',
      notBefore: new Date(OPENS),
      notAfter: new Date(CLOSES),
    })
    assert.deepEqual(key.publicKey, PUBLIC_KEY)
    assert.equal(key.passphraseProtected, false)
    assert.equal('passphrase' in (key as object), false)
    assert.equal(calls(stub)[0]?.method, 'POST')
    assert.equal(calls(stub)[0]?.path, TC)
    assert.deepEqual(sentBody(stub), {
      alias: 'quarter-close',
      algorithm_id: 'rsa_3072',
      not_before: OPENS,
      not_after: CLOSES,
    })
  } finally {
    await stub.close()
  }
})

test('creating a protected key returns the passphrase, and it is the only call that ever does', async () => {
  const stub = await startStub(
    withToken((req, res) => {
      if (req.method === 'POST') {
        return created(res, {
          ...keyBody({ passphrase_protected: true }),
          public_key: PUBLIC_KEY_B64,
          passphrase: 'cGFzcy1waHJhc2UtMzItYnl0ZXM=',
        })
      }
      ok(res, keyBody({ passphrase_protected: true }))
    }),
  )
  try {
    const keys = clientFor(stub).vault.timeConstrainedKeys
    const key = await keys.create({
      alias: 'quarter-close',
      algorithmId: 'rsa_3072',
      notBefore: new Date(OPENS),
      notAfter: new Date(CLOSES),
      passphraseProtected: true,
      description: 'closes the quarter',
    })

    // The union narrows on the flag, so the passphrase is reachable without a
    // runtime check a caller could forget.
    assert.equal(key.passphraseProtected, true)
    if (key.passphraseProtected) {
      assert.equal(key.passphrase, 'cGFzcy1waHJhc2UtMzItYnl0ZXM=')
    }
    assert.equal(sentBody(stub)['passphrase_protected'], true)
    assert.equal(sentBody(stub)['description'], 'closes the quarter')

    // Reading the key back must never carry it. It is shown once and cannot be
    // recovered, and a read that returned it would make that claim false.
    const read = await keys.get({ alias: 'quarter-close' })
    assert.equal('passphrase' in (read as object), false)
  } finally {
    await stub.close()
  }
})

test('a protected key created without a passphrase in the response is a broken response', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      created(res, { ...keyBody({ passphrase_protected: true }), public_key: PUBLIC_KEY_B64 })
    }),
  )
  try {
    // Failing here is the only chance anyone gets. The passphrase is never sent
    // again, so a caller who stored nothing would discover it at the first
    // decrypt, with the key already unusable and nothing to do about it.
    await assert.rejects(
      clientFor(stub).vault.timeConstrainedKeys.create({
        alias: 'quarter-close',
        algorithmId: 'rsa_3072',
        notBefore: new Date(OPENS),
        notAfter: new Date(CLOSES),
        passphraseProtected: true,
      }),
      (error: unknown) =>
        error instanceof ProtocolError &&
        error.code === 'ESD-007' &&
        error.details['field'] === 'passphrase',
    )
  } finally {
    await stub.close()
  }
})

test('reading one key names it in the path, and an unknown alias is a not-found failure', async () => {
  const stub = await startStub(
    withToken((req, res, index) => {
      if (index === 1) return ok(res, keyBody())
      fail(res, 404, { message: 'not found' })
    }),
  )
  try {
    const keys = clientFor(stub).vault.timeConstrainedKeys
    const key = await keys.get({ alias: 'quarter-close' })
    assert.equal(key.alias, 'quarter-close')
    assert.equal(calls(stub)[0]?.path, `${TC}/quarter-close`)
    await assert.rejects(keys.get({ alias: 'ghost' }), NotFoundError)
  } finally {
    await stub.close()
  }
})

test('an alias with awkward characters is escaped into the path', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, keyBody({ alias: 'a b/c' }))
    }),
  )
  try {
    await clientFor(stub).vault.timeConstrainedKeys.get({ alias: 'a b/c' })
    assert.equal(calls(stub)[0]?.path, `${TC}/a%20b%2Fc`)
  } finally {
    await stub.close()
  }
})

test('the public key comes back as bytes, with no version to name', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, { algorithm_id: 'rsa_3072', public_key: PUBLIC_KEY_B64 })
    }),
  )
  try {
    const result = await clientFor(stub).vault.timeConstrainedKeys.publicKey({
      alias: 'quarter-close',
    })
    assert.deepEqual(result.publicKey, PUBLIC_KEY)
    assert.equal(result.algorithmId, 'rsa_3072')
    assert.equal(calls(stub)[0]?.method, 'GET')
    assert.equal(calls(stub)[0]?.path, `${TC}/quarter-close/public-key`)
  } finally {
    await stub.close()
  }
})

test('encrypting works while the window is still closed, and carries no passphrase', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, { ciphertext: CIPHERTEXT_B64 })
    }),
  )
  try {
    // The whole point of these keys: seal data now that nobody can open until a
    // chosen date. Encrypting uses the public half, so a pending window does not
    // stand in the way and no passphrase is involved.
    const ciphertext = await clientFor(stub).vault.timeConstrainedKeys.encrypt({
      alias: 'quarter-close',
      plaintext: PLAINTEXT,
      label: LABEL,
    })
    assert.deepEqual(ciphertext, CIPHERTEXT)
    assert.equal(calls(stub)[0]?.path, `${TC}/quarter-close/encrypt`)
    assert.deepEqual(sentBody(stub), { plaintext: PLAINTEXT_B64, label: LABEL_B64 })
  } finally {
    await stub.close()
  }
})

test('an omitted label is left off the request rather than sent as null', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, { ciphertext: CIPHERTEXT_B64 })
    }),
  )
  try {
    await clientFor(stub).vault.timeConstrainedKeys.encrypt({
      alias: 'quarter-close',
      plaintext: PLAINTEXT,
    })
    assert.equal('label' in sentBody(stub), false)
  } finally {
    await stub.close()
  }
})

test('decrypting sends the ciphertext, label and passphrase, and returns the plaintext', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, { plaintext: PLAINTEXT_B64 })
    }),
  )
  try {
    const plaintext = await clientFor(stub).vault.timeConstrainedKeys.decrypt({
      alias: 'quarter-close',
      ciphertext: CIPHERTEXT,
      label: LABEL,
      passphrase: 'secret-value',
    })
    assert.deepEqual(plaintext, PLAINTEXT)
    assert.deepEqual(sentBody(stub), {
      ciphertext: CIPHERTEXT_B64,
      label: LABEL_B64,
      passphrase: 'secret-value',
    })
  } finally {
    await stub.close()
  }
})

test('the passphrase travels in the body only, never in the path or the query', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, { plaintext: PLAINTEXT_B64 })
    }),
  )
  try {
    await clientFor(stub).vault.timeConstrainedKeys.decrypt({
      alias: 'quarter-close',
      ciphertext: CIPHERTEXT,
      passphrase: 'secret-value',
    })
    // A secret in a URL survives in access logs, proxy logs and browser history
    // long after the request is over.
    assert.equal(calls(stub)[0]?.path.includes('secret-value'), false)
    assert.equal(calls(stub)[0]?.path.includes('?'), false)
  } finally {
    await stub.close()
  }
})

test('encapsulating takes an options object and sends no fields, and decapsulating returns the secret', async () => {
  const stub = await startStub(
    withToken((req, res) => {
      if (req.path.endsWith('/encapsulate')) {
        return ok(res, { ciphertext: CIPHERTEXT_B64, shared_secret: SECRET_B64 })
      }
      ok(res, { shared_secret: SECRET_B64 })
    }),
  )
  try {
    const keys = clientFor(stub).vault.timeConstrainedKeys
    const sealed = await keys.encapsulate({ alias: 'kem-key' })
    assert.deepEqual(sealed.ciphertext, CIPHERTEXT)
    assert.deepEqual(sealed.sharedSecret, SECRET)
    // qshield reads no body here at all. The options object exists so a
    // parameter can be added later without breaking anyone.
    assert.deepEqual(sentBody(stub), {})

    const recovered = await keys.decapsulate({
      alias: 'kem-key',
      ciphertext: CIPHERTEXT,
      passphrase: 'secret-value',
    })
    assert.deepEqual(recovered, SECRET)
    assert.deepEqual(JSON.parse(calls(stub)[1]?.body ?? '{}'), {
      ciphertext: CIPHERTEXT_B64,
      passphrase: 'secret-value',
    })
  } finally {
    await stub.close()
  }
})

test('extending sends the new closing time and the passphrase, and returns the moved key', async () => {
  const later = '2026-11-01T00:00:00.000Z'
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, keyBody({ passphrase_protected: true, not_after: later, window_status: 'active' }))
    }),
  )
  try {
    const key = await clientFor(stub).vault.timeConstrainedKeys.extend({
      alias: 'quarter-close',
      notAfter: new Date(later),
      passphrase: 'secret-value',
    })
    assert.deepEqual(key.notAfter, new Date(later))
    assert.equal(calls(stub)[0]?.path, `${TC}/quarter-close/extend`)
    assert.deepEqual(sentBody(stub), { new_not_after: later, passphrase: 'secret-value' })
  } finally {
    await stub.close()
  }
})

test('extending without a passphrase omits the field, and a protected key then refuses', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      fail(res, 403, { code: 'EVT-009', message: 'the passphrase was missing or wrong' })
    }),
  )
  try {
    await assert.rejects(
      clientFor(stub).vault.timeConstrainedKeys.extend({
        alias: 'quarter-close',
        notAfter: new Date('2026-11-01T00:00:00.000Z'),
      }),
      (error: unknown) => error instanceof TimeKeyPassphraseRejectedError,
    )
    assert.equal('passphrase' in sentBody(stub), false)
  } finally {
    await stub.close()
  }
})

test('destroying answers nothing, and a later use of the key is the expired failure', async () => {
  const stub = await startStub(
    withToken((req, res) => {
      if (req.path.endsWith('/destroy')) return ok(res, { status: 'destroyed' })
      fail(res, 410, { code: 'EVT-008', message: 'this key can no longer be used' })
    }),
  )
  try {
    const keys = clientFor(stub).vault.timeConstrainedKeys
    const answer = await keys.destroy({ alias: 'quarter-close', passphrase: 'secret-value' })
    assert.equal(answer, undefined)
    assert.equal(calls(stub)[0]?.method, 'POST')
    assert.equal(calls(stub)[0]?.path, `${TC}/quarter-close/destroy`)
    assert.deepEqual(sentBody(stub), { passphrase: 'secret-value' })

    // Destroying shreds the material now. There is no tombstone to read and
    // nothing to undo, so every later use answers the same way an expired key
    // does.
    await assert.rejects(
      keys.decrypt({ alias: 'quarter-close', ciphertext: CIPHERTEXT }),
      (error: unknown) => error instanceof TimeKeyExpiredError,
    )
  } finally {
    await stub.close()
  }
})

test('decrypting before the window opens is its own failure, and it is worth retrying', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      fail(res, 422, {
        code: 'EVT-007',
        message: 'this key cannot be used yet',
        description: 'the key is before the start of its validity window',
      })
    }),
  )
  try {
    await assert.rejects(
      clientFor(stub).vault.timeConstrainedKeys.decrypt({
        alias: 'quarter-close',
        ciphertext: CIPHERTEXT,
      }),
      (error: unknown) =>
        error instanceof TimeKeyNotYetValidError &&
        error.code === 'EVT-007' &&
        error.status === 422 &&
        !(error instanceof TimeKeyExpiredError),
    )
    // Nothing is retried for the caller. The wait is theirs to decide, and it
    // may be days.
    assert.equal(calls(stub).length, 1)
  } finally {
    await stub.close()
  }
})

test('decrypting after the window closes is a different failure, and it is permanent', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      fail(res, 410, {
        code: 'EVT-008',
        message: 'this key can no longer be used',
        description: 'the key is past the end of its validity window',
      })
    }),
  )
  try {
    await assert.rejects(
      clientFor(stub).vault.timeConstrainedKeys.decrypt({
        alias: 'quarter-close',
        ciphertext: CIPHERTEXT,
      }),
      (error: unknown) =>
        error instanceof TimeKeyExpiredError &&
        error.code === 'EVT-008' &&
        error.status === 410 &&
        !(error instanceof TimeKeyNotYetValidError),
    )
    // The material is gone. Repeating the call could never succeed.
    assert.equal(calls(stub).length, 1)
  } finally {
    await stub.close()
  }
})

test('too early, too late and a wrong passphrase are three classes that never overlap', async () => {
  const stub = await startStub(
    withToken((_req, res, index) => {
      if (index === 1) return fail(res, 422, { code: 'EVT-007', message: 'not yet' })
      if (index === 2) return fail(res, 410, { code: 'EVT-008', message: 'too late' })
      fail(res, 403, { code: 'EVT-009', message: 'wrong passphrase' })
    }),
  )
  try {
    const keys = clientFor(stub).vault.timeConstrainedKeys
    const caught: unknown[] = []
    for (let i = 0; i < 3; i++) {
      await keys
        .decrypt({ alias: 'quarter-close', ciphertext: CIPHERTEXT, passphrase: 'x' })
        .catch((error: unknown) => caught.push(error))
    }

    // This is the property the whole phase exists for. A caller writing a retry
    // loop has to be able to tell "wait and try later" from "this data is gone
    // for good" from "you typed the wrong secret", and the three lead to three
    // completely different actions.
    assert.ok(caught[0] instanceof TimeKeyNotYetValidError)
    assert.ok(caught[1] instanceof TimeKeyExpiredError)
    assert.ok(caught[2] instanceof TimeKeyPassphraseRejectedError)

    assert.equal(caught[0] instanceof TimeKeyExpiredError, false)
    assert.equal(caught[1] instanceof TimeKeyPassphraseRejectedError, false)
    assert.equal(caught[2] instanceof TimeKeyNotYetValidError, false)
    // And the passphrase failure is not a permission refusal, whatever its
    // status says. The caller is allowed to use the key; they gave the wrong
    // secret.
    assert.equal(caught[2] instanceof TimeKeyExpiredError, false)
  } finally {
    await stub.close()
  }
})

test('the feature not being licensed is a licensing failure, not a permission one', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      fail(res, 403, {
        code: 'EGN-000',
        message: 'vault feature not available in your license',
        details: { reason: 'feature_unlicensed' },
      })
    }),
  )
  try {
    await assert.rejects(
      clientFor(stub).vault.timeConstrainedKeys.list(),
      (error: unknown) => error instanceof NotLicensedError,
    )
  } finally {
    await stub.close()
  }
})

test('a sealed vault is a typed failure on a time-constrained key route and is NOT repeated', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      fail(res, 503, { code: 'EVT-001', message: 'the vault is locked' })
    }),
  )
  try {
    await assert.rejects(
      clientFor(stub).vault.timeConstrainedKeys.decrypt({
        alias: 'quarter-close',
        ciphertext: CIPHERTEXT,
      }),
      (error: unknown) => error instanceof VaultSealedError && error.code === 'EVT-001',
    )
    // Unsealing is a human act that can take hours. Repeating the call would
    // hang the caller instead of telling them what to do.
    assert.equal(calls(stub).length, 1, 'a sealed vault must not be retried')
  } finally {
    await stub.close()
  }
})

test('a key missing a field it is defined to carry is a broken response, not a key with a gap', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      const body = keyBody()
      delete body['window_status']
      ok(res, body)
    }),
  )
  try {
    await assert.rejects(
      clientFor(stub).vault.timeConstrainedKeys.get({ alias: 'quarter-close' }),
      (error: unknown) =>
        error instanceof ProtocolError && error.details['field'] === 'window_status',
    )
  } finally {
    await stub.close()
  }
})
