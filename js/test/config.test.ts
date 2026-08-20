import assert from 'node:assert/strict'
import test from 'node:test'

import { ConfigurationError, QShieldClient } from '../src/index.js'
import { resolveConfig } from '../src/internal/config.js'
import { CREDENTIAL } from './support/stub.js'

const good = { baseUrl: 'https://qshield.example.com', ...CREDENTIAL }

test('a well formed configuration is accepted', () => {
  const config = resolveConfig(good)
  assert.equal(config.baseUrl, 'https://qshield.example.com')
  assert.equal(config.timeoutMs, 30_000)
})

test('a trailing slash is removed so a route can never be joined twice', () => {
  assert.equal(resolveConfig({ ...good, baseUrl: 'https://q.example.com/' }).baseUrl, 'https://q.example.com')
})

test('a path prefix is kept, because qshield can sit under one', () => {
  assert.equal(resolveConfig({ ...good, baseUrl: 'https://q.example.com/qshield/' }).baseUrl, 'https://q.example.com/qshield')
})

test('an insecure address is refused', () => {
  assert.throws(
    () => resolveConfig({ ...good, baseUrl: 'http://qshield.example.com' }),
    (error: unknown) => error instanceof ConfigurationError && 'baseUrl' in error.details,
  )
})

test('an insecure address on the local machine is allowed, for development', () => {
  assert.equal(resolveConfig({ ...good, baseUrl: 'http://localhost:8080' }).baseUrl, 'http://localhost:8080')
})

test('a malformed client id fails before anything is sent, and names the field', () => {
  assert.throws(
    () => new QShieldClient({ ...good, clientId: 'not-a-client-id' }),
    (error: unknown) =>
      error instanceof ConfigurationError &&
      error.code === 'ESD-001' &&
      error.details['clientId'] !== undefined,
  )
})

test('a malformed client secret names the secret, not the id', () => {
  assert.throws(
    () => new QShieldClient({ ...good, clientSecret: 'qss_short' }),
    (error: unknown) =>
      error instanceof ConfigurationError &&
      error.details['clientSecret'] !== undefined &&
      error.details['clientId'] === undefined,
  )
})

test('the failure never quotes the secret back', () => {
  try {
    new QShieldClient({ ...good, clientSecret: 'qss_this-one-is-wrong' })
    assert.fail('expected a failure')
  } catch (error) {
    const text = JSON.stringify(error instanceof Error ? [error.message, (error as ConfigurationError).details] : error)
    assert.equal(text.includes('this-one-is-wrong'), false)
  }
})

test('an address carrying credentials is refused', () => {
  assert.throws(() => resolveConfig({ ...good, baseUrl: 'https://user:pass@q.example.com' }), ConfigurationError)
})

test('a timeout that is not a positive number is refused', () => {
  assert.throws(() => resolveConfig({ ...good, timeoutMs: 0 }), ConfigurationError)
})

test('the version check must be one of the two settings', () => {
  assert.throws(
    () =>
      new QShieldClient({ ...good, versionCheck: 'strict' as never }),
    (error: unknown) => {
      assert.ok(error instanceof ConfigurationError)
      assert.deepEqual(error.details, { versionCheck: "must be 'warn' or 'off'" })
      return true
    },
  )
})

test('the version check defaults to warning', () => {
  assert.equal(resolveConfig(good).versionCheck, 'warn')
})
