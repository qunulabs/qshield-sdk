/**
 * The token lifecycle. Everything the SDK does starts with one of these
 * exchanges, so this is the part it is worth being fussy about.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { clientWith, requesterOf } from '../src/client.js'
import {
  AuthenticationError,
  CancelledError,
  ConnectionError,
  HumanOnlyError,
  NotLicensedError,
} from '../src/index.js'
// fromEntry builds a failure the SDK detected itself. It is deliberately not
// published, so this one import stays internal.
import { fromEntry } from '../src/internal/errors.js'
import { ConnectionFailed } from '../src/internal/codes.js'
import { type HttpResponse, type Transport, TransportError } from '../src/internal/http.js'
import { CREDENTIAL, fail, ok, startStub, token, tokenError, type Stub } from './support/stub.js'

const TOKEN = '/api/v1/auth/token'
const THING = '/api/v1/system/info'

function clientFor(stub: Stub, now?: () => number) {
  return requesterOf(clientWith({ baseUrl: stub.baseUrl, ...CREDENTIAL }, now === undefined ? {} : { now }))
}

function tokenCalls(stub: Stub): number {
  return stub.requests.filter((r) => r.path === TOKEN).length
}

test('the credential is exchanged once and the token is reused', async () => {
  const stub = await startStub((req, res) => {
    if (req.path === TOKEN) return token(res, 'tok-1')
    ok(res, { version: 'v0.14.0' })
  })
  try {
    const api = clientFor(stub)
    await api.json({ method: 'GET', path: THING })
    await api.json({ method: 'GET', path: THING })
    assert.equal(tokenCalls(stub), 1)
  } finally {
    await stub.close()
  }
})

test('the exchange sends a form body, not JSON, and no basic authentication', async () => {
  const stub = await startStub((req, res) => {
    if (req.path === TOKEN) return token(res, 'tok-1')
    ok(res, {})
  })
  try {
    await clientFor(stub).json({ method: 'GET', path: THING })
    const exchange = stub.requests[0]
    assert.ok(exchange)
    assert.match(String(exchange.headers['content-type']), /application\/x-www-form-urlencoded/)
    assert.equal(exchange.headers['authorization'], undefined)
    assert.match(exchange.body, /grant_type=client_credentials/)
    assert.match(exchange.body, /client_secret=/)
  } finally {
    await stub.close()
  }
})

test('the token is replaced before it expires, not after', async () => {
  let clock = 1_000_000
  const stub = await startStub((req, res) => {
    if (req.path === TOKEN) return token(res, `tok-${tokenCalls(stub)}`, 900)
    ok(res, {})
  })
  try {
    const api = clientFor(stub, () => clock)
    await api.json({ method: 'GET', path: THING })
    // Fourteen minutes in: inside the renewal margin, so it is replaced early.
    clock += 14 * 60 * 1000 + 1_000
    await api.json({ method: 'GET', path: THING })
    assert.equal(tokenCalls(stub), 2)
  } finally {
    await stub.close()
  }
})

test('a burst of calls produces exactly one exchange', async () => {
  const stub = await startStub((req, res) => {
    if (req.path === TOKEN) {
      // Slow enough that every caller is waiting when the first one asks.
      setTimeout(() => token(res, 'tok-1'), 25)
      return
    }
    ok(res, {})
  })
  try {
    const api = clientFor(stub)
    await Promise.all(Array.from({ length: 20 }, () => api.json({ method: 'GET', path: THING })))
    assert.equal(tokenCalls(stub), 1)
  } finally {
    await stub.close()
  }
})

test('a token refused mid-life is replaced once and the call is repeated once', async () => {
  let refuse = true
  const stub = await startStub((req, res) => {
    if (req.path === TOKEN) return token(res, `tok-${tokenCalls(stub)}`)
    if (refuse) {
      refuse = false
      return fail(res, 401, { code: 'EGN-002', message: 'token rejected', description: 'mint again' })
    }
    ok(res, { version: 'v0.14.0' })
  })
  try {
    const result = await clientFor(stub).json<{ version: string }>({ method: 'GET', path: THING })
    assert.equal(result.data.version, 'v0.14.0')
    assert.equal(tokenCalls(stub), 2)
    assert.equal(stub.requests.filter((r) => r.path === THING).length, 2)
  } finally {
    await stub.close()
  }
})

test('a token that keeps being refused fails once, and does not loop', async () => {
  const stub = await startStub((req, res) => {
    if (req.path === TOKEN) return token(res, 'tok-1')
    fail(res, 401, { code: 'EGN-002', message: 'token rejected', description: 'mint again' })
  })
  try {
    await assert.rejects(clientFor(stub).json({ method: 'GET', path: THING }), AuthenticationError)
    assert.equal(stub.requests.filter((r) => r.path === THING).length, 2)
  } finally {
    await stub.close()
  }
})

test('a rejected credential is an authentication failure carrying the code', async () => {
  const stub = await startStub((req, res) => {
    tokenError(res, 401, 'invalid_client', 'client authentication failed', 'EGN-005')
  })
  try {
    await assert.rejects(clientFor(stub).json({ method: 'GET', path: THING }), (error: unknown) => {
      assert.ok(error instanceof AuthenticationError)
      assert.equal(error.code, 'EGN-005')
      assert.equal(error.details['oauth_error'], 'invalid_client')
      return true
    })
  } finally {
    await stub.close()
  }
})

test('service accounts not licensed is a licensing failure, not a credential one', async () => {
  const stub = await startStub((req, res) => {
    tokenError(res, 403, 'invalid_client', 'service accounts are not enabled', 'EGN-006')
  })
  try {
    await assert.rejects(clientFor(stub).json({ method: 'GET', path: THING }), NotLicensedError)
  } finally {
    await stub.close()
  }
})

test('an account holding a human-only permission is reported as needing a person', async () => {
  const stub = await startStub((req, res) => {
    tokenError(res, 403, 'invalid_client', 'ask an administrator to review its roles', 'EGN-014')
  })
  try {
    await assert.rejects(clientFor(stub).json({ method: 'GET', path: THING }), HumanOnlyError)
  } finally {
    await stub.close()
  }
})

test('the rate-limit refusal on the token route arrives enveloped, and is waited out', async () => {
  let refused = false
  const stub = await startStub((req, res) => {
    if (req.path === TOKEN) {
      if (!refused) {
        refused = true
        // This one refusal speaks the platform envelope, unlike every other
        // answer on this route.
        return fail(res, 429, { code: 'EGN-027', message: 'too many requests', description: 'slow down' })
      }
      return token(res, 'tok-1')
    }
    ok(res, {})
  })
  try {
    await clientFor(stub).json({ method: 'GET', path: THING })
    assert.equal(tokenCalls(stub), 2)
  } finally {
    await stub.close()
  }
})

/** A response built by hand, for the tests that substitute the transport. */
function jsonResponse(status: number, payload: unknown, headers: Record<string, string> = {}): HttpResponse {
  return {
    status,
    headers: new Headers({ 'content-type': 'application/json', ...headers }),
    body: new TextEncoder().encode(JSON.stringify(payload)),
  }
}

const GRANTED = { access_token: 'tok-1', token_type: 'Bearer', expires_in: 900 }
const PAYLOAD = { success: true, data: { version: 'v0.14.0' }, request_id: 'req-1' }

test('one caller cancelling does not fail the others waiting for the same exchange', async () => {
  // The exchange is shared because the token route's allowance is shared. It
  // follows that it belongs to no single caller, so no single caller may end it
  // for everybody else.
  const controller = new AbortController()
  let release: (() => void) | undefined
  const stub = await startStub((req, res) => {
    if (req.path === TOKEN) {
      void new Promise<void>((resolve) => {
        release = resolve
      }).then(() => {
        token(res, 'tok-1')
      })
      return
    }
    ok(res, { version: 'v0.14.0' })
  })
  try {
    const api = clientFor(stub)
    const cancelled = api.json({ method: 'GET', path: THING, signal: controller.signal })
    const healthy = api.json({ method: 'GET', path: THING })

    await new Promise((resolve) => setTimeout(resolve, 20))
    controller.abort()
    await assert.rejects(cancelled, CancelledError)

    release?.()
    const result = await healthy
    assert.deepEqual(result.data, { version: 'v0.14.0' })
    assert.equal(tokenCalls(stub), 1, 'the cancellation must not have started a second exchange')
  } finally {
    await stub.close()
  }
})

test('a connection that never opened on the token route is tried again', async () => {
  // The same rule as any other call: nothing was sent, so nothing can happen
  // twice. Unwrapping the failure inside the exchange used to hide the verdict
  // from the retry layer, so a cold client gave up on the first refusal.
  let exchanges = 0
  const transport: Transport = (request) => {
    if (request.url.endsWith(TOKEN)) {
      exchanges += 1
      if (exchanges === 1) {
        throw new TransportError({
          error: fromEntry(ConnectionError, ConnectionFailed),
          unsent: true,
          repeatable: true,
        })
      }
      return Promise.resolve(jsonResponse(200, GRANTED))
    }
    return Promise.resolve(jsonResponse(200, PAYLOAD))
  }

  const api = requesterOf(
    clientWith({ baseUrl: 'https://qshield.example.com', ...CREDENTIAL }, { transport }),
  )
  const result = await api.json({ method: 'GET', path: THING })
  assert.deepEqual(result.data, { version: 'v0.14.0' })
  assert.equal(exchanges, 2)
})

test('the token route is rate limited per address, so its Retry-After is honoured', async () => {
  // Every process a customer runs behind one address shares this allowance, so
  // what the server says about coming back is worth more than a guess.
  let exchanges = 0
  const transport: Transport = (request) => {
    if (request.url.endsWith(TOKEN)) {
      exchanges += 1
      if (exchanges === 1) {
        return Promise.resolve(
          jsonResponse(
            429,
            { success: false, error: { code: 'EGN-027', message: 'too many', description: 'slow down' } },
            { 'retry-after': '0' },
          ),
        )
      }
      return Promise.resolve(jsonResponse(200, GRANTED))
    }
    return Promise.resolve(jsonResponse(200, PAYLOAD))
  }

  const api = requesterOf(
    clientWith({ baseUrl: 'https://qshield.example.com', ...CREDENTIAL }, { transport }),
  )
  const startedAt = Date.now()
  await api.json({ method: 'GET', path: THING })
  const waited = Date.now() - startedAt

  assert.equal(exchanges, 2)
  // The shortest jittered backoff is 125 ms. Coming back sooner than that is
  // only possible if the server's own answer was read.
  assert.ok(waited < 100, `waited ${waited} ms, so the Retry-After was ignored`)
})
