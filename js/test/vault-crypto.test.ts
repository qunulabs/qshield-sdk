/**
 * The crypto operations and data keys: client.vault.keys.* and
 * client.vault.dataKeys.
 *
 * Three properties here are worth more than the route coverage, and each one is
 * a thing a customer's integration would otherwise get quietly wrong.
 *
 * BINARY IS BYTES, BOTH WAYS. Every message, signature, ciphertext and key
 * crosses the wire base64 encoded, and none of that reaches the public API.
 * These tests send real bytes and assert the exact base64 on the wire, so a
 * conversion that goes missing in one direction cannot pass.
 *
 * A BAD SIGNATURE IS FALSE, NOT AN EXCEPTION - and nothing else is. Getting that
 * wrong either way is a security bug: throwing pushes callers into a catch block
 * where a failure to check looks like a failure to match, and answering false for
 * a key that could not perform the check tells them their data was tampered with.
 *
 * NOTHING IS QUIETLY ABSENT. A data key arrives whole or the call fails.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { clientWith } from '../src/client.js'
import {
  ConflictError,
  NotFoundError,
  NotLicensedError,
  PermissionError,
  ProtocolError,
  RequestError,
  ValidationError,
  VaultSealedError,
} from '../src/index.js'
import { CREDENTIAL, fail, ok, startStub, token, type Stub } from './support/stub.js'

const TOKEN = '/api/v1/auth/token'
const KEYS = '/api/v1/vault/keys'
const DATAKEY = '/api/v1/vault/datakey'

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

// Deliberately awkward values: a zero byte, a high byte, and a length that does
// not divide by three, so base64 padding is exercised rather than assumed.
const MESSAGE = bytes(0, 1, 254, 255, 42)
const SIGNATURE = bytes(9, 8, 7, 6)
const CIPHERTEXT = bytes(200, 0, 13)
const AAD = bytes(1, 2, 3)

const MESSAGE_B64 = 'AAH+/yo='
const SIGNATURE_B64 = 'CQgHBg=='
const CIPHERTEXT_B64 = 'yAAN'
const AAD_B64 = 'AQID'

test('signing sends the message as bytes and returns the signature and its version', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, { signature: SIGNATURE_B64, version: 3 })
    }),
  )
  try {
    const result = await clientFor(stub).vault.keys.sign({ alias: 'signer', message: MESSAGE })
    assert.deepEqual(result.signature, SIGNATURE)
    assert.equal(result.version, 3)
    assert.equal(calls(stub)[0]?.method, 'POST')
    assert.equal(calls(stub)[0]?.path, `${KEYS}/signer/sign`)
    assert.deepEqual(sentBody(stub), { message: MESSAGE_B64 })
  } finally {
    await stub.close()
  }
})

test('an omitted version is left off the request rather than sent as null', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, { signature: SIGNATURE_B64, version: 1 })
    }),
  )
  try {
    await clientFor(stub).vault.keys.sign({ alias: 'signer', message: MESSAGE })
    assert.equal('version' in sentBody(stub), false)
  } finally {
    await stub.close()
  }
})

test('a named version reaches the request', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, { signature: SIGNATURE_B64, version: 2 })
    }),
  )
  try {
    await clientFor(stub).vault.keys.sign({ alias: 'signer', message: MESSAGE, version: 2 })
    assert.equal(sentBody(stub)['version'], 2)
  } finally {
    await stub.close()
  }
})

test('a matching signature verifies as true', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, { valid: true })
    }),
  )
  try {
    const valid = await clientFor(stub).vault.keys.verify({
      alias: 'signer',
      message: MESSAGE,
      signature: SIGNATURE,
    })
    assert.equal(valid, true)
    assert.equal(calls(stub)[0]?.path, `${KEYS}/signer/verify`)
    assert.deepEqual(sentBody(stub), { message: MESSAGE_B64, signature: SIGNATURE_B64 })
  } finally {
    await stub.close()
  }
})

test('a bad signature answers false and does NOT throw', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, { valid: false })
    }),
  )
  try {
    // The whole point of the method. If this ever throws, callers end up
    // treating "could not check" and "did not match" as the same thing.
    const valid = await clientFor(stub).vault.keys.verify({
      alias: 'signer',
      message: MESSAGE,
      signature: SIGNATURE,
    })
    assert.equal(valid, false)
  } finally {
    await stub.close()
  }
})

test('verify throws rather than answering false when the key is missing', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      fail(res, 404, { code: 'EVT-002', message: 'no such key' })
    }),
  )
  try {
    await assert.rejects(
      clientFor(stub).vault.keys.verify({
        alias: 'absent',
        message: MESSAGE,
        signature: SIGNATURE,
      }),
      (error: unknown) => error instanceof NotFoundError && error.code === 'EVT-002',
    )
  } finally {
    await stub.close()
  }
})

test('verify throws rather than answering false when the key was deleted', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      fail(res, 409, { code: 'EVT-011', message: 'the key was deleted' })
    }),
  )
  try {
    // Answering false here would tell the caller their data had been tampered
    // with, when in fact somebody deleted the key.
    await assert.rejects(
      clientFor(stub).vault.keys.verify({ alias: 'gone', message: MESSAGE, signature: SIGNATURE }),
      (error: unknown) => error instanceof ConflictError && error.code === 'EVT-011',
    )
  } finally {
    await stub.close()
  }
})

test('verify throws when the key cannot perform the check at all', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      fail(res, 422, { code: 'EVT-014', message: 'this key cannot do that' })
    }),
  )
  try {
    await assert.rejects(
      clientFor(stub).vault.keys.verify({
        alias: 'encrypter',
        message: MESSAGE,
        signature: SIGNATURE,
      }),
      (error: unknown) => error instanceof RequestError && error.code === 'EVT-014',
    )
  } finally {
    await stub.close()
  }
})

test('encrypting returns the ciphertext and the version that produced it', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, { ciphertext: CIPHERTEXT_B64, version: 4 })
    }),
  )
  try {
    const result = await clientFor(stub).vault.keys.encrypt({ alias: 'box', plaintext: MESSAGE })
    assert.deepEqual(result.ciphertext, CIPHERTEXT)
    assert.equal(result.version, 4)
    assert.equal(calls(stub)[0]?.path, `${KEYS}/box/encrypt`)
    assert.deepEqual(sentBody(stub), { plaintext: MESSAGE_B64 })
  } finally {
    await stub.close()
  }
})

test('decrypting returns the plaintext bytes', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, { plaintext: MESSAGE_B64 })
    }),
  )
  try {
    const plaintext = await clientFor(stub).vault.keys.decrypt({
      alias: 'box',
      ciphertext: CIPHERTEXT,
    })
    assert.deepEqual(plaintext, MESSAGE)
    assert.equal(calls(stub)[0]?.path, `${KEYS}/box/decrypt`)
    assert.deepEqual(sentBody(stub), { ciphertext: CIPHERTEXT_B64 })
  } finally {
    await stub.close()
  }
})

test('encrypt then decrypt round trips, carrying the additional data both ways', async () => {
  const stub = await startStub(
    withToken((_req, res, index) => {
      if (index === 1) return ok(res, { ciphertext: CIPHERTEXT_B64, version: 1 })
      return ok(res, { plaintext: MESSAGE_B64 })
    }),
  )
  try {
    const client = clientFor(stub)
    const sealed = await client.vault.keys.encrypt({
      alias: 'box',
      plaintext: MESSAGE,
      additionalData: AAD,
    })
    const opened = await client.vault.keys.decrypt({
      alias: 'box',
      ciphertext: sealed.ciphertext,
      additionalData: AAD,
    })
    assert.deepEqual(opened, MESSAGE)

    const encryptBody = JSON.parse(calls(stub)[0]?.body ?? '{}') as Record<string, unknown>
    const decryptBody = JSON.parse(calls(stub)[1]?.body ?? '{}') as Record<string, unknown>
    // The wire name is aad; the public name is additionalData. Both halves must
    // carry it, because a decrypt that drops it silently fails to open.
    assert.equal(encryptBody['aad'], AAD_B64)
    assert.equal(decryptBody['aad'], AAD_B64)
    assert.equal(decryptBody['ciphertext'], CIPHERTEXT_B64)
  } finally {
    await stub.close()
  }
})

test('omitted additional data is left off the request entirely', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, { ciphertext: CIPHERTEXT_B64, version: 1 })
    }),
  )
  try {
    await clientFor(stub).vault.keys.encrypt({ alias: 'box', plaintext: MESSAGE })
    assert.equal('aad' in sentBody(stub), false)
  } finally {
    await stub.close()
  }
})

test('a message authentication code comes back as bytes with its version', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, { mac: SIGNATURE_B64, version: 2 })
    }),
  )
  try {
    const result = await clientFor(stub).vault.keys.hmac({ alias: 'mac', message: MESSAGE })
    assert.deepEqual(result.mac, SIGNATURE)
    assert.equal(result.version, 2)
    assert.equal(calls(stub)[0]?.path, `${KEYS}/mac/hmac`)
    assert.deepEqual(sentBody(stub), { message: MESSAGE_B64 })
  } finally {
    await stub.close()
  }
})

test('encapsulating sends nothing but the key and returns both halves', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, { ciphertext: CIPHERTEXT_B64, shared_secret: MESSAGE_B64, version: 1 })
    }),
  )
  try {
    const result = await clientFor(stub).vault.keys.encapsulate({ alias: 'kem' })
    assert.deepEqual(result.ciphertext, CIPHERTEXT)
    assert.deepEqual(result.sharedSecret, MESSAGE)
    assert.equal(result.version, 1)
    assert.equal(calls(stub)[0]?.path, `${KEYS}/kem/encapsulate`)
    // An empty object, not an absent body: the route decodes a JSON body even
    // though it needs nothing from it.
    assert.deepEqual(sentBody(stub), {})
  } finally {
    await stub.close()
  }
})

test('decapsulating recovers the shared secret', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, { shared_secret: MESSAGE_B64 })
    }),
  )
  try {
    const secret = await clientFor(stub).vault.keys.decapsulate({
      alias: 'kem',
      ciphertext: CIPHERTEXT,
    })
    assert.deepEqual(secret, MESSAGE)
    assert.equal(calls(stub)[0]?.path, `${KEYS}/kem/decapsulate`)
    assert.deepEqual(sentBody(stub), { ciphertext: CIPHERTEXT_B64 })
  } finally {
    await stub.close()
  }
})

test('a data key arrives as the key to use and the wrapped copy to store', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, { wrapped: CIPHERTEXT_B64, plaintext: MESSAGE_B64 })
    }),
  )
  try {
    const dek = await clientFor(stub).vault.dataKeys.generate({})
    assert.deepEqual(dek.key, MESSAGE)
    assert.deepEqual(dek.wrapped, CIPHERTEXT)
    assert.equal(calls(stub)[0]?.method, 'POST')
    assert.equal(calls(stub)[0]?.path, DATAKEY)
    // The SDK always asks for the key itself, and never supplies a transport
    // key: a caller is never asked to produce a key pair to receive a key.
    assert.deepEqual(sentBody(stub), { return_plaintext: true })
  } finally {
    await stub.close()
  }
})

test('a chosen data key algorithm reaches the request', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, { wrapped: CIPHERTEXT_B64, plaintext: MESSAGE_B64 })
    }),
  )
  try {
    await clientFor(stub).vault.dataKeys.generate({ algorithmId: 'chacha20_poly1305' })
    assert.deepEqual(sentBody(stub), {
      return_plaintext: true,
      algorithm_id: 'chacha20_poly1305',
    })
  } finally {
    await stub.close()
  }
})

test('a data key refused for want of permission raises the typed failure', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      fail(res, 403, {
        code: 'EVT-010',
        message: 'you are not allowed to receive a data key in the clear',
        description: 'grant vault:datakey:plaintext',
      })
    }),
  )
  try {
    await assert.rejects(
      clientFor(stub).vault.dataKeys.generate({}),
      (error: unknown) =>
        error instanceof PermissionError &&
        error.code === 'EVT-010' &&
        error.description.includes('vault:datakey:plaintext'),
    )
  } finally {
    await stub.close()
  }
})

test('a data key response missing the key is a broken response, not a half a key', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      // The shape this route used to answer with when the caller lacked the
      // permission. It must never become a DataKey with an empty half.
      ok(res, { wrapped: CIPHERTEXT_B64 })
    }),
  )
  try {
    await assert.rejects(
      clientFor(stub).vault.dataKeys.generate({}),
      (error: unknown) => error instanceof ProtocolError,
    )
  } finally {
    await stub.close()
  }
})

test('unwrapping a stored data key returns the key', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, { plaintext: MESSAGE_B64 })
    }),
  )
  try {
    const key = await clientFor(stub).vault.dataKeys.unwrap({ wrapped: CIPHERTEXT })
    assert.deepEqual(key, MESSAGE)
    assert.equal(calls(stub)[0]?.path, `${DATAKEY}/unwrap`)
    assert.deepEqual(sentBody(stub), { wrapped: CIPHERTEXT_B64 })
  } finally {
    await stub.close()
  }
})

test('a wrapped copy that does not open raises the typed failure', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      fail(res, 422, { code: 'EVT-017', message: 'this wrapped data key could not be opened' })
    }),
  )
  try {
    await assert.rejects(
      clientFor(stub).vault.dataKeys.unwrap({ wrapped: CIPHERTEXT }),
      (error: unknown) => error instanceof RequestError && error.code === 'EVT-017',
    )
  } finally {
    await stub.close()
  }
})

test('the crypto feature being unlicensed is distinguishable from a missing permission', async () => {
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
    // Both answer 403. Only the reason tells "buy this" from "grant this".
    await assert.rejects(
      clientFor(stub).vault.keys.sign({ alias: 'signer', message: MESSAGE }),
      (error: unknown) => error instanceof NotLicensedError,
    )
  } finally {
    await stub.close()
  }
})

test('a sealed vault is a typed failure on a crypto route and is NOT repeated', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      fail(res, 503, { code: 'EVT-001', message: 'the vault is locked' })
    }),
  )
  try {
    await assert.rejects(
      clientFor(stub).vault.keys.decrypt({ alias: 'box', ciphertext: CIPHERTEXT }),
      (error: unknown) => error instanceof VaultSealedError && error.code === 'EVT-001',
    )
    // Unsealing is a human act that can take hours. Repeating the call would
    // hang the caller instead of telling them what to do.
    assert.equal(calls(stub).length, 1, 'a sealed vault must not be retried')
  } finally {
    await stub.close()
  }
})

test('a payload over the vault request cap is refused once, not chunked or repeated', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      fail(res, 413, { code: 'EGN-000', message: 'request body too large' })
    }),
  )
  try {
    // Base64 inflates by about a third, so the practical ceiling is lower than
    // the raw cap. The SDK neither splits the payload nor retries it: the
    // server's refusal is the answer.
    const oversized = new Uint8Array(1024)
    await assert.rejects(
      clientFor(stub).vault.keys.encrypt({ alias: 'box', plaintext: oversized }),
      (error: unknown) => error instanceof RequestError && error.status === 413,
    )
    assert.equal(calls(stub).length, 1, 'an oversized payload must not be split or repeated')
  } finally {
    await stub.close()
  }
})

// A refusal that names the field the caller got wrong is a validation failure,
// wherever in qshield it came from.
//
// Both of these answer 400 and carry a field-to-reason map, exactly like the
// platform's own validation refusal, and both are fixed by sending a different
// value. Leaving them as a bare request failure would mean a caller that catches
// ValidationError to read `details` silently misses the two refusals a wrong
// algorithm produces, which are the likeliest mistakes on these routes.
test('an unusable algorithm is a validation failure, and the field is named', async () => {
  const stub = await startStub(withToken((_req, res) => {
    fail(res, 400, {
      code: 'EVT-012',
      message: 'that algorithm is not one this deployment offers',
      description: 'the algorithm_id names no algorithm in this catalogue',
      details: { algorithm_id: "names no algorithm in this deployment's catalogue" },
    })
  }))
  try {
    await assert.rejects(
      clientFor(stub).vault.dataKeys.generate({ algorithmId: 'aes_999' }),
      (error: unknown) => {
        assert.ok(error instanceof ValidationError)
        assert.equal(error.code, 'EVT-012')
        assert.ok(error.details['algorithm_id'], 'the offending field must be readable')
        return true
      },
    )
  } finally {
    await stub.close()
  }
})

test('an unusable transport key is a validation failure naming its field', async () => {
  const stub = await startStub(withToken((_req, res) => {
    fail(res, 400, {
      code: 'EVT-016',
      message: 'the public key sent with this request could not be used',
      description: 'the transport_public_key could not be read as DER SubjectPublicKeyInfo',
      details: { transport_public_key: 'could not be read as DER SubjectPublicKeyInfo' },
    })
  }))
  try {
    await assert.rejects(clientFor(stub).vault.dataKeys.generate({}), (error: unknown) => {
      assert.ok(error instanceof ValidationError)
      assert.equal(error.code, 'EVT-016')
      return true
    })
  } finally {
    await stub.close()
  }
})
