/**
 * The first product namespace: client.vault.keys.
 *
 * These tests pin two different things, and the second matters more. The first
 * is the obvious one - the right method reaches the right route and the payload
 * comes back typed. The second is the set of behaviours a customer's integration
 * depends on and could not discover from the route table: that a bare 204 and an
 * enveloped 200 both mean the same thing, that a sealed vault is not repeated,
 * that a cloud key is visible as one rather than mysteriously unrotatable, and
 * that a deleted key stays in the list.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { clientWith } from '../src/client.js'
import {
  ConflictError,
  NotFoundError,
  NotLicensedError,
  ProtocolError,
  QShieldError,
  RequestError,
  ValidationError,
  VaultSealedError,
} from '../src/index.js'
import {
  CREDENTIAL,
  created,
  fail,
  noContent,
  ok,
  startStub,
  token,
  type Stub,
} from './support/stub.js'

const TOKEN = '/api/v1/auth/token'
const KEYS = '/api/v1/vault/keys'

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

/** A local key, as qshield sends one. */
const LOCAL_KEY = {
  id: '5a1b0f6e-0000-4000-8000-000000000001',
  alias: 'signer',
  algorithm_id: 'ed25519',
  purpose: 'signature',
  current_version: 1,
  state: 'active',
  origin: 'local',
  created_at: '2026-08-19T10:00:00Z',
  updated_at: '2026-08-19T10:00:00Z',
}

/** A key imported from a customer's own cloud key service. */
const CLOUD_KEY = {
  ...LOCAL_KEY,
  id: '5a1b0f6e-0000-4000-8000-000000000002',
  alias: 'imported',
  origin: 'cloud',
  connection_id: 'c0ffee00-0000-4000-8000-000000000003',
  external_id: 'arn:aws:kms:eu-west-1:1234:key/abc',
  external_alias: 'alias/imported',
}

test('the keys are listed, oldest first, exactly as qshield ordered them', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, [LOCAL_KEY, CLOUD_KEY])
    }),
  )
  try {
    const keys = await clientFor(stub).vault.keys.list()
    assert.equal(keys.length, 2)
    assert.equal(keys[0]?.alias, 'signer')
    assert.equal(keys[1]?.alias, 'imported')
    assert.equal(calls(stub)[0]?.method, 'GET')
    assert.equal(calls(stub)[0]?.path, KEYS)
  } finally {
    await stub.close()
  }
})

test('a workspace with no keys yields an empty list, not a failure', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, [])
    }),
  )
  try {
    assert.deepEqual(await clientFor(stub).vault.keys.list(), [])
  } finally {
    await stub.close()
  }
})

test('a deleted key stays in the list, reported as deleted', async () => {
  // Deletion is a tombstone, not a hidden row. A caller filtering for usable
  // keys has to be able to see the difference, so the state is never hidden.
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, [{ ...LOCAL_KEY, state: 'deleted' }])
    }),
  )
  try {
    const keys = await clientFor(stub).vault.keys.list()
    assert.equal(keys[0]?.state, 'deleted')
  } finally {
    await stub.close()
  }
})

test('a cloud key carries its provider identity as one object', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, CLOUD_KEY)
    }),
  )
  try {
    const key = await clientFor(stub).vault.keys.get({ alias: 'imported' })
    assert.equal(key.origin, 'cloud')
    assert.equal(key.cloud?.externalId, 'arn:aws:kms:eu-west-1:1234:key/abc')
    assert.equal(key.cloud?.connectionId, 'c0ffee00-0000-4000-8000-000000000003')
  } finally {
    await stub.close()
  }
})

test('a local key carries no provider identity at all', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, LOCAL_KEY)
    }),
  )
  try {
    const key = await clientFor(stub).vault.keys.get({ alias: 'signer' })
    assert.equal(key.origin, 'local')
    assert.equal(key.cloud, undefined)
    assert.equal(calls(stub)[0]?.path, `${KEYS}/signer`)
  } finally {
    await stub.close()
  }
})

test('creating a key sends the wire names and accepts the 201', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      created(res, { ...LOCAL_KEY, rotation_interval: '720h0m0s' })
    }),
  )
  try {
    const key = await clientFor(stub).vault.keys.create({
      alias: 'signer',
      algorithmId: 'ed25519',
      purpose: 'signature',
      rotationInterval: '720h',
    })
    const sent = JSON.parse(calls(stub)[0]?.body ?? '{}') as Record<string, unknown>
    assert.equal(calls(stub)[0]?.method, 'POST')
    assert.deepEqual(sent, {
      alias: 'signer',
      algorithm_id: 'ed25519',
      purpose: 'signature',
      rotation_interval: '720h',
    })
    // qshield normalises the duration, so what comes back is equivalent and not
    // identical. A caller must never compare these by string.
    assert.equal(key.rotationInterval, '720h0m0s')
  } finally {
    await stub.close()
  }
})

test('a key created without a rotation schedule sends no interval and reports none', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      created(res, LOCAL_KEY)
    }),
  )
  try {
    const key = await clientFor(stub).vault.keys.create({
      alias: 'signer',
      algorithmId: 'ed25519',
      purpose: 'signature',
    })
    const sent = JSON.parse(calls(stub)[0]?.body ?? '{}') as Record<string, unknown>
    assert.equal('rotation_interval' in sent, false)
    assert.equal(key.rotationInterval, undefined)
    assert.equal(key.nextRotationAt, undefined)
  } finally {
    await stub.close()
  }
})

test('timestamps arrive as dates, not as the strings qshield sent', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, { ...LOCAL_KEY, next_rotation_at: '2026-09-18T10:00:00Z' })
    }),
  )
  try {
    const key = await clientFor(stub).vault.keys.get({ alias: 'signer' })
    assert.ok(key.createdAt instanceof Date)
    assert.equal(key.createdAt.toISOString(), '2026-08-19T10:00:00.000Z')
    assert.equal(key.nextRotationAt?.toISOString(), '2026-09-18T10:00:00.000Z')
  } finally {
    await stub.close()
  }
})

test('the version history comes back as metadata and carries no key material', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, {
        alias: 'signer',
        current_version: 2,
        versions: [
          {
            version: 1,
            kek_version: 1,
            state: 'active',
            has_public_key: true,
            created_at: '2026-08-19T10:00:00Z',
          },
          {
            version: 2,
            kek_version: 1,
            state: 'active',
            has_public_key: true,
            created_at: '2026-08-19T11:00:00Z',
          },
        ],
      })
    }),
  )
  try {
    const history = await clientFor(stub).vault.keys.versions({ alias: 'signer' })
    assert.equal(history.currentVersion, 2)
    assert.equal(history.versions.length, 2)
    assert.equal(history.versions[1]?.hasPublicKey, true)
    assert.equal(calls(stub)[0]?.path, `${KEYS}/signer/versions`)
  } finally {
    await stub.close()
  }
})

test('a public key arrives as bytes, never as the base64 it travelled in', async () => {
  const spki = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x00, 0xff])
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, {
        alias: 'signer',
        algorithm_id: 'ed25519',
        version: 2,
        public_key: Buffer.from(spki).toString('base64'),
      })
    }),
  )
  try {
    const result = await clientFor(stub).vault.keys.publicKey({ alias: 'signer', version: 2 })
    assert.deepEqual(result.publicKey, spki)
    assert.equal(result.version, 2)
    assert.equal(calls(stub)[0]?.path, `${KEYS}/signer/public-key?version=2`)
  } finally {
    await stub.close()
  }
})

test('a public key read with no version asks for none and gets the current one', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, { alias: 'signer', algorithm_id: 'ed25519', version: 1, public_key: '' })
    }),
  )
  try {
    await clientFor(stub).vault.keys.publicKey({ alias: 'signer' })
    assert.equal(calls(stub)[0]?.path, `${KEYS}/signer/public-key`)
  } finally {
    await stub.close()
  }
})

test('a damaged public key is refused rather than quietly truncated', async () => {
  // Node's base64 decoder skips what it does not recognise, which would turn a
  // damaged key into a shorter key that looks perfectly valid.
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, { alias: 'signer', algorithm_id: 'ed25519', version: 1, public_key: 'not base64!!' })
    }),
  )
  try {
    await assert.rejects(
      clientFor(stub).vault.keys.publicKey({ alias: 'signer' }),
      (error: unknown) => error instanceof ProtocolError,
    )
  } finally {
    await stub.close()
  }
})

test('rotating a key sends no body and returns the new current version', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, { ...LOCAL_KEY, current_version: 2 })
    }),
  )
  try {
    const key = await clientFor(stub).vault.keys.rotate({ alias: 'signer' })
    assert.equal(key.currentVersion, 2)
    assert.equal(calls(stub)[0]?.method, 'POST')
    assert.equal(calls(stub)[0]?.path, `${KEYS}/signer/rotate`)
    assert.equal(calls(stub)[0]?.body, '')
  } finally {
    await stub.close()
  }
})

test('rotating a cloud key is refused, and says where to rotate it instead', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      fail(res, 409, {
        code: 'EVT-004',
        message: "This key lives in your cloud provider's key service.",
        description: 'Rotation is not available for a key whose origin is a cloud provider.',
        details: { reason: 'cloud_origin_key' },
      })
    }),
  )
  try {
    await assert.rejects(
      clientFor(stub).vault.keys.rotate({ alias: 'imported' }),
      (error: unknown) => error instanceof ConflictError && error.code === 'EVT-004',
    )
  } finally {
    await stub.close()
  }
})

test('deleting a key turns the bare 204 into nothing at all', async () => {
  // This is the ONE route in the vault tree that answers 204 with no body and no
  // envelope. Every other delete answers 200 with a status object.
  const stub = await startStub(
    withToken((_req, res) => {
      noContent(res)
    }),
  )
  try {
    assert.equal(await clientFor(stub).vault.keys.delete({ alias: 'signer' }), undefined)
    assert.equal(calls(stub)[0]?.method, 'DELETE')
    assert.equal(calls(stub)[0]?.path, `${KEYS}/signer`)
  } finally {
    await stub.close()
  }
})

test('deleting a key that is already deleted succeeds and changes nothing', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      noContent(res)
    }),
  )
  try {
    const keys = clientFor(stub).vault.keys
    await keys.delete({ alias: 'signer' })
    await keys.delete({ alias: 'signer' })
    assert.equal(calls(stub).length, 2)
  } finally {
    await stub.close()
  }
})

test('an alias that does not exist is reported as not found', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      fail(res, 404, {
        code: 'EVT-002',
        message: 'That key does not exist in this workspace.',
        description: 'No key carries the alias in the request path.',
      })
    }),
  )
  try {
    await assert.rejects(
      clientFor(stub).vault.keys.get({ alias: 'nope' }),
      (error: unknown) => error instanceof NotFoundError && error.code === 'EVT-002',
    )
  } finally {
    await stub.close()
  }
})

test('a symmetric key asked for a public half says so, rather than not found', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      fail(res, 422, {
        code: 'EVT-003',
        message: 'This kind of key has no public half to share.',
        description: 'A public key was requested for a symmetric or message-authentication key.',
      })
    }),
  )
  try {
    await assert.rejects(
      clientFor(stub).vault.keys.publicKey({ alias: 'sym' }),
      (error: unknown) =>
        error instanceof RequestError &&
        !(error instanceof NotFoundError) &&
        error.code === 'EVT-003',
    )
  } finally {
    await stub.close()
  }
})

test('a licensed key limit is a licensing failure, not a permission one', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      fail(res, 403, {
        code: 'EVT-006',
        message: "This deployment's license does not allow any more keys.",
        description: 'Key creation was refused because the deployment has reached its maximum.',
        details: { reason: 'feature_limit_reached' },
      })
    }),
  )
  try {
    await assert.rejects(
      clientFor(stub).vault.keys.create({
        alias: 'one-too-many',
        algorithmId: 'aes_256_gcm',
        purpose: 'encryption',
      }),
      (error: unknown) => error instanceof NotLicensedError && error.code === 'EVT-006',
    )
  } finally {
    await stub.close()
  }
})

test('a deployment without vault at all is a licensing failure, though it carries no code', async () => {
  // That path has not been given a code yet, so the machine-readable reason is
  // the only thing separating "buy this" from "grant this". Reading it is what
  // stops a customer chasing a permission that would never have helped.
  const stub = await startStub(
    withToken((_req, res) => {
      fail(res, 403, {
        code: 'EGN-000',
        message: 'vault feature not available in your license',
        description: 'vault feature not available in your license',
        details: { reason: 'feature_unlicensed' },
      })
    }),
  )
  try {
    await assert.rejects(
      clientFor(stub).vault.keys.list(),
      (error: unknown) => error instanceof NotLicensedError,
    )
  } finally {
    await stub.close()
  }
})

test('an unusable version is a validation failure carrying the field that is wrong', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      fail(res, 400, {
        code: 'EGN-019',
        message: 'The request could not be accepted.',
        description: 'One or more fields failed validation.',
        details: { version: 'must be a positive integer' },
      })
    }),
  )
  try {
    await assert.rejects(
      clientFor(stub).vault.keys.publicKey({ alias: 'signer', version: -1 }),
      (error: unknown) =>
        error instanceof ValidationError &&
        error.details['version'] === 'must be a positive integer',
    )
  } finally {
    await stub.close()
  }
})

test('a sealed vault is reported as sealed and the call is never repeated', async () => {
  // Unsealing is a human act that can take hours. Repeating the call only makes
  // the customer wait, so exactly one request must reach qshield.
  for (const operation of ['list', 'rotate'] as const) {
    const stub = await startStub(
      withToken((_req, res) => {
        fail(res, 503, {
          code: 'EVT-001',
          message: 'The vault is locked, so keys cannot be used right now.',
          description: 'The vault is sealed and its whole data plane is refusing work.',
        })
      }),
    )
    try {
      const keys = clientFor(stub).vault.keys
      const call = operation === 'list' ? keys.list() : keys.rotate({ alias: 'signer' })
      await assert.rejects(
        call,
        (error: unknown) => error instanceof VaultSealedError && error.code === 'EVT-001',
      )
      assert.equal(calls(stub).length, 1, `${operation} was repeated against a sealed vault`)
    } finally {
      await stub.close()
    }
  }
})

test('a response missing a field the SDK is defined to receive is refused', async () => {
  // Substituting an empty alias or the current time would put invented data into
  // a customer's records, which is far worse than failing where it happened.
  const stub = await startStub(
    withToken((_req, res) => {
      const { alias: _alias, ...withoutAlias } = LOCAL_KEY
      ok(res, withoutAlias)
    }),
  )
  try {
    await assert.rejects(
      clientFor(stub).vault.keys.get({ alias: 'signer' }),
      (error: unknown) => error instanceof ProtocolError,
    )
  } finally {
    await stub.close()
  }
})

test('a cancelled call fails as one of the SDK own failures', async () => {
  const stub = await startStub(
    withToken((_req, res) => {
      ok(res, [])
    }),
  )
  try {
    const controller = new AbortController()
    controller.abort()
    await assert.rejects(
      clientFor(stub).vault.keys.list({ signal: controller.signal }),
      (error: unknown) => error instanceof QShieldError,
    )
  } finally {
    await stub.close()
  }
})
