/**
 * Reading responses, choosing failures, and deciding what is worth repeating.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { clientWith, requesterOf } from '../src/client.js'
import {
  CancelledError,
  ConflictError,
  GoneError,
  HumanOnlyError,
  NotFoundError,
  NotLicensedError,
  PermissionError,
  QShieldError,
  RateLimitError,
  RequestError,
  ServerError,
  TimeoutError,
  ValidationError,
  VaultSealedError,
} from '../src/index.js'
import type { QShieldClientOptions } from '../src/internal/config.js'
import { CREDENTIAL, fail, ok, startStub, token, type Stub } from './support/stub.js'

const TOKEN = '/api/v1/auth/token'
const THING = '/api/v1/vault/keys'

function clientFor(stub: Stub, extra: Partial<QShieldClientOptions> = {}) {
  return requesterOf(clientWith({ baseUrl: stub.baseUrl, ...CREDENTIAL, ...extra }, {}))
}

/** Answers the token exchange, and hands everything else to the test. */
function withToken(respond: Parameters<typeof startStub>[0]): Parameters<typeof startStub>[0] {
  return (req, res, index) => {
    if (req.path === TOKEN) return token(res, 'tok-1')
    return respond(req, res, index)
  }
}

test('the payload is unwrapped and handed back on its own', async () => {
  const stub = await startStub(withToken((_req, res) => {
    ok(res, [{ id: 'key-1' }])
  }))
  try {
    const result = await clientFor(stub).json<{ id: string }[]>({ method: 'GET', path: THING })
    assert.deepEqual(result.data, [{ id: 'key-1' }])
    assert.equal(result.requestId, 'req-test-1')
  } finally {
    await stub.close()
  }
})

test('paging information survives the unwrapping', async () => {
  const stub = await startStub(withToken((_req, res) => {
    ok(res, [], { meta: { page: 2, page_size: 25, total: 137 } })
  }))
  try {
    const result = await clientFor(stub).json({ method: 'GET', path: THING })
    assert.deepEqual(result.page, { page: 2, pageSize: 25, total: 137 })
  } finally {
    await stub.close()
  }
})

test('advisories on a successful response reach the warning handler', async () => {
  const seen: string[] = []
  const stub = await startStub(withToken((_req, res) => {
    ok(res, { done: true }, { warnings: ['the agent was offline'] })
  }))
  try {
    await clientFor(stub, { onWarning: (w) => seen.push(w) }).json({ method: 'GET', path: THING })
    assert.deepEqual(seen, ['the agent was offline'])
  } finally {
    await stub.close()
  }
})

test('an empty response is a result with no payload, not a failure', async () => {
  const stub = await startStub(withToken((_req, res) => {
    res.statusCode = 204
    res.setHeader('x-request-id', 'req-204')
    res.end()
  }))
  try {
    const result = await clientFor(stub).json({ method: 'DELETE', path: `${THING}/key-1` })
    assert.equal(result.data, undefined)
    assert.equal(result.requestId, 'req-204')
  } finally {
    await stub.close()
  }
})

test('a download comes back as bytes, with its type and suggested filename', async () => {
  const pem = '-----BEGIN CERTIFICATE-----\nnot a real certificate\n-----END CERTIFICATE-----\n'
  const stub = await startStub(withToken((_req, res) => {
    res.statusCode = 200
    res.setHeader('content-type', 'application/x-pem-file')
    res.setHeader('content-disposition', 'attachment; filename="chain.pem"')
    res.end(pem)
  }))
  try {
    const result = await clientFor(stub).bytes(
      { method: 'GET', path: '/api/v1/com/pki/certificates/c1/download' },
      'application/x-pem-file',
    )
    assert.equal(new TextDecoder().decode(result.bytes), pem)
    assert.equal(result.contentType, 'application/x-pem-file')
    assert.equal(result.filename, 'chain.pem')
  } finally {
    await stub.close()
  }
})

const classified: [string, number, new (...args: never[]) => QShieldError][] = [
  ['EGN-008', 403, PermissionError],
  ['EGN-009', 403, HumanOnlyError],
  ['EGN-017', 403, NotLicensedError],
  ['EGN-018', 403, NotLicensedError],
  ['EGN-019', 400, ValidationError],
  ['EGN-024', 404, NotFoundError],
  ['EGN-025', 409, ConflictError],
  ['EGN-026', 410, GoneError],
  ['EGN-027', 429, RateLimitError],
  ['EGN-029', 500, ServerError],
  ['EVT-001', 503, VaultSealedError],
  ['EPK-006', 503, VaultSealedError],
  ['EVT-006', 403, NotLicensedError],
  ['EPK-001', 403, HumanOnlyError],
]

for (const [code, status, Kind] of classified) {
  test(`${code} is reported as ${Kind.name}`, async () => {
    const stub = await startStub(withToken((_req, res) => {
      fail(res, status, { code, message: 'operator sentence', description: 'developer sentence' })
    }))
    try {
      await assert.rejects(clientFor(stub).json({ method: 'GET', path: THING }), (error: unknown) => {
        assert.ok(error instanceof Kind)
        assert.equal((error as QShieldError).code, code)
        assert.equal((error as QShieldError).message, 'operator sentence')
        assert.equal((error as QShieldError).description, 'developer sentence')
        assert.equal((error as QShieldError).requestId, 'req-test-err')
        assert.equal((error as QShieldError).status, status)
        return true
      })
    } finally {
      await stub.close()
    }
  })
}

test('the placeholder code identifies nothing, so the status decides', async () => {
  const stub = await startStub(withToken((_req, res) => {
    fail(res, 409, { code: 'EGN-000', message: 'that did not work', description: 'that did not work' })
  }))
  try {
    await assert.rejects(clientFor(stub).json({ method: 'GET', path: THING }), ConflictError)
  } finally {
    await stub.close()
  }
})

test('a code the SDK has never seen still produces a sensible failure', async () => {
  const stub = await startStub(withToken((_req, res) => {
    fail(res, 404, { code: 'ECR-042', message: 'no such scan', description: 'check the identifier' })
  }))
  try {
    await assert.rejects(clientFor(stub).json({ method: 'GET', path: THING }), (error: unknown) => {
      assert.ok(error instanceof NotFoundError)
      assert.equal((error as QShieldError).code, 'ECR-042')
      return true
    })
  } finally {
    await stub.close()
  }
})

test('a validation failure carries the offending fields', async () => {
  const stub = await startStub(withToken((_req, res) => {
    fail(res, 400, {
      code: 'EGN-019',
      message: 'check the form',
      description: 'one or more fields are invalid',
      details: { name: 'required' },
    })
  }))
  try {
    await assert.rejects(clientFor(stub).json({ method: 'POST', path: THING, body: {} }), (error: unknown) => {
      assert.ok(error instanceof ValidationError)
      assert.equal(error.details['name'], 'required')
      return true
    })
  } finally {
    await stub.close()
  }
})

test('something that is not qshield at all still fails usefully', async () => {
  const stub = await startStub(withToken((_req, res) => {
    res.statusCode = 502
    res.setHeader('content-type', 'text/html')
    res.end('<html>gateway error</html>')
  }))
  try {
    await assert.rejects(clientFor(stub).json({ method: 'GET', path: THING }), (error: unknown) => {
      assert.ok(error instanceof ServerError)
      assert.equal(error.status, 502)
      return true
    })
  } finally {
    await stub.close()
  }
})

test('too many requests is waited out and the call succeeds', async () => {
  let refused = false
  const stub = await startStub(withToken((_req, res) => {
    if (!refused) {
      refused = true
      res.setHeader('retry-after', '0')
      return fail(res, 429, { code: 'EGN-027', message: 'too many', description: 'slow down' })
    }
    ok(res, { id: 'key-1' })
  }))
  try {
    const result = await clientFor(stub).json<{ id: string }>({ method: 'GET', path: THING })
    assert.equal(result.data.id, 'key-1')
    assert.equal(stub.requests.filter((r) => r.path === THING).length, 2)
  } finally {
    await stub.close()
  }
})

test('a sealed vault is never repeated', async () => {
  const stub = await startStub(withToken((_req, res) => {
    fail(res, 503, { code: 'EVT-001', message: 'the vault is sealed', description: 'unseal it' })
  }))
  try {
    await assert.rejects(clientFor(stub).json({ method: 'POST', path: `${THING}/k1/sign`, body: {} }), VaultSealedError)
    assert.equal(stub.requests.filter((r) => r.path !== TOKEN).length, 1)
  } finally {
    await stub.close()
  }
})

test('no other refusal is repeated', async () => {
  const stub = await startStub(withToken((_req, res) => {
    fail(res, 409, { code: 'EGN-025', message: 'wrong state', description: 'change the state first' })
  }))
  try {
    await assert.rejects(clientFor(stub).json({ method: 'POST', path: THING, body: {} }), ConflictError)
    assert.equal(stub.requests.filter((r) => r.path === THING).length, 1)
  } finally {
    await stub.close()
  }
})

test('a request that changes state is never repeated after a timeout', async () => {
  const stub = await startStub(withToken((_req, res) => {
    // Never answers. The client gives up on its own.
    void res
  }))
  try {
    await assert.rejects(
      clientFor(stub, { timeoutMs: 120 }).json({ method: 'POST', path: THING, body: { name: 'k' } }),
      TimeoutError,
    )
    assert.equal(stub.requests.filter((r) => r.path === THING).length, 1)
  } finally {
    await stub.close()
  }
})

// The 401 replay is the ONE path that repeats a request which changes state, and
// C1 is where that starts to matter: creating and rotating a key are POSTs, and
// issuing one twice is not the same as issuing it once.
//
// It is safe for one reason only, and the reason is worth stating because it is
// not a property of this package: qshield decides a 401 in the middleware that
// parses the token, before any handler runs, so a refused request was never
// carried out. These two tests pin the bound rather than the safety - the replay
// happens exactly once, and a token qshield keeps refusing produces one clear
// failure instead of a loop.
test('a request that changes state is replayed once, and only once, after a token refusal', async () => {
  let refuse = true
  const stub = await startStub(withToken((_req, res) => {
    if (refuse) {
      refuse = false
      return fail(res, 401, { code: 'EGN-002', message: 'token rejected', description: 'mint again' })
    }
    ok(res, { id: 'key-1' })
  }))
  try {
    await clientFor(stub).json({ method: 'POST', path: THING, body: { alias: 'k' } })
    const sent = stub.requests.filter((r) => r.path === THING)
    assert.equal(sent.length, 2, 'the refused attempt and one replay, never more')
    assert.deepEqual(
      sent.map((r) => r.body),
      [JSON.stringify({ alias: 'k' }), JSON.stringify({ alias: 'k' })],
      'the replay must carry the same body, not a rebuilt one',
    )
  } finally {
    await stub.close()
  }
})

test('a token qshield keeps refusing does not replay a state-changing call forever', async () => {
  const stub = await startStub(withToken((_req, res) => {
    fail(res, 401, { code: 'EGN-002', message: 'token rejected', description: 'mint again' })
  }))
  try {
    await assert.rejects(
      clientFor(stub).json({ method: 'POST', path: THING, body: { alias: 'k' } }),
      QShieldError,
    )
    assert.equal(stub.requests.filter((r) => r.path === THING).length, 2)
  } finally {
    await stub.close()
  }
})

test('a request that changes state is not repeated when qshield fails internally', async () => {
  const stub = await startStub(withToken((_req, res) => {
    fail(res, 500, { code: 'EGN-020', message: 'internal', description: 'try later' })
  }))
  try {
    await assert.rejects(
      clientFor(stub).json({ method: 'POST', path: THING, body: { alias: 'k' } }),
      ServerError,
    )
    assert.equal(
      stub.requests.filter((r) => r.path === THING).length,
      1,
      'a 500 may mean the work was done, so repeating it could do the work twice',
    )
  } finally {
    await stub.close()
  }
})

test('a bad request that is not a validation failure is still a request failure', async () => {
  const stub = await startStub(withToken((_req, res) => {
    fail(res, 400, { code: 'EGN-030', message: 'rejected', description: 'the request was rejected' })
  }))
  try {
    await assert.rejects(clientFor(stub).json({ method: 'POST', path: THING, body: {} }), RequestError)
  } finally {
    await stub.close()
  }
})

test('a call can be cancelled while it is in flight', async () => {
  const controller = new AbortController()
  const stub = await startStub(withToken((_req, res) => {
    setTimeout(() => controller.abort(), 20)
    void res
  }))
  try {
    await assert.rejects(
      clientFor(stub).json({ method: 'GET', path: THING, signal: controller.signal }),
      CancelledError,
    )
  } finally {
    await stub.close()
  }
})

test('a call cancelled before it starts makes no request at all', async () => {
  const controller = new AbortController()
  controller.abort()
  const stub = await startStub(withToken((_req, res) => {
    ok(res, {})
  }))
  try {
    await assert.rejects(
      clientFor(stub).json({ method: 'GET', path: THING, signal: controller.signal }),
      CancelledError,
    )
    assert.equal(stub.requests.length, 0)
  } finally {
    await stub.close()
  }
})

test('a connection that was never made is tried again, then reported', async () => {
  // Nothing is listening on this port, so every attempt is refused outright.
  const api = requesterOf(clientWith({ baseUrl: 'http://127.0.0.1:1', ...CREDENTIAL }, {}))
  await assert.rejects(api.json({ method: 'GET', path: THING }), (error: unknown) => {
    assert.ok(error instanceof QShieldError)
    assert.equal(error.code, 'ESD-003')
    return true
  })
})

test('cancelling during a wait between attempts raises the SDK\'s own cancellation', async () => {
  // A wait between two attempts is still part of the call. Rejecting it with the
  // runtime's abort reason would hand the caller something that is not a
  // QShieldError, and catching QShieldError has to catch everything.
  const controller = new AbortController()
  const stub = await startStub((req, res) => {
    if (req.path === TOKEN) return token(res, 'tok-1')
    res.setHeader('retry-after', '10')
    setTimeout(() => controller.abort(), 20)
    fail(res, 429, { code: 'EGN-027', message: 'too many', description: 'slow down' })
  })
  try {
    await assert.rejects(
      clientFor(stub).json({ method: 'GET', path: THING, signal: controller.signal }),
      (error: unknown) => {
        assert.ok(error instanceof QShieldError, 'a cancelled wait must still be an SDK failure')
        assert.ok(error instanceof CancelledError)
        assert.equal(error.code, 'ESD-006')
        return true
      },
    )
  } finally {
    await stub.close()
  }
})

test('a download filename that will not decode does not fail the download', async () => {
  // The bytes are the answer and the filename is a suggestion. A stray percent
  // sign would otherwise raise a decoding error from outside the SDK's own set
  // of failures, which is exactly what a caller cannot be asked to handle.
  const stub = await startStub((req, res) => {
    if (req.path === TOKEN) return token(res, 'tok-1')
    res.setHeader('content-type', 'application/x-pem-file')
    res.setHeader('content-disposition', 'attachment; filename="100%.pem"')
    res.statusCode = 200
    res.end('-----BEGIN CERTIFICATE-----')
  })
  try {
    const result = await clientFor(stub).bytes(
      { method: 'GET', path: THING },
      'application/x-pem-file',
    )
    assert.equal(result.filename, '100%.pem')
    assert.equal(result.contentType, 'application/x-pem-file')
  } finally {
    await stub.close()
  }
})
