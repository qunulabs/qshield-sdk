/**
 * Trust is the customer's to configure, and the SDK's to explain when it is
 * missing.
 *
 * The SDK deliberately offers no way to supply a certificate authority and no
 * way to skip verification. The failure it produces has to be good enough to
 * act on without either, because it is the most likely thing a customer meets
 * on their first run: Node ignores the machine trust store unless it is told
 * not to, so an internal root installed on the host does nothing on its own.
 *
 * The server here uses the committed test-only certificate, which nothing
 * trusts. That is the point.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { clientWith, requesterOf } from '../src/client.js'
import { QShieldError } from '../src/index.js'
import { CREDENTIAL, ok, startUntrustedTlsStub } from './support/stub.js'

test('an untrusted server certificate is named as such, with the fix', async () => {
  const stub = await startUntrustedTlsStub((_req, res) => {
    ok(res, {})
  })
  try {
    const api = requesterOf(clientWith({ baseUrl: stub.baseUrl, ...CREDENTIAL }, {}))
    await assert.rejects(api.json({ method: 'GET', path: '/api/v1/system/info' }), (error: unknown) => {
      assert.ok(error instanceof QShieldError)
      assert.equal(error.code, 'ESD-004')
      // The developer message has to name what to change, or the customer is
      // left guessing at a TLS failure with no lever in the SDK to pull.
      assert.match(error.description, /--use-system-ca/)
      assert.match(error.description, /NODE_EXTRA_CA_CERTS/)
      return true
    })
    // The connection never completed, so qshield never saw a credential.
    assert.equal(stub.requests.length, 0)
  } finally {
    await stub.close()
  }
})
