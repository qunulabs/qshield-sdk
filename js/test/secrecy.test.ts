/**
 * Two properties that are security rather than style, so they are pinned rather
 * than trusted to review.
 *
 * The SDK never writes request or response content anywhere. Bodies carry key
 * material, private keys and secrets, and there is no flag that turns logging
 * on.
 *
 * The SDK never changes the host application's network or trust settings. It is
 * a convenience layer over the qshield API and nothing more: a library that
 * reaches into a process's trust store, its global agent or its environment can
 * weaken a customer's security without the customer ever knowing.
 */

import assert from 'node:assert/strict'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'

import { clientWith, requesterOf } from '../src/client.js'
import { CREDENTIAL, fail, ok, startStub, token } from './support/stub.js'

const SECRET_MARKER = 'PRIVATE-KEY-MATERIAL-MARKER'

/** Short enough to survive the runtime's truncation of a parse error message. */
const LEAK_MARKER = 'LEAKME'

function sourceFiles(dir: string): string[] {
  const out: string[] = []
  for (const name of readdirSync(dir)) {
    const full = path.join(dir, name)
    if (statSync(full).isDirectory()) out.push(...sourceFiles(full))
    else if (full.endsWith('.ts')) out.push(full)
  }
  return out
}

const sources = sourceFiles(path.join(process.cwd(), 'src')).map((file) => ({
  file,
  text: readFileSync(file, 'utf8'),
}))

const forbidden: [RegExp, string][] = [
  [/\bconsole\s*\./, 'writes to the console'],
  [/NODE_TLS_REJECT_UNAUTHORIZED/, 'disables certificate verification'],
  [/rejectUnauthorized/, 'touches certificate verification'],
  [/setDefaultCACertificates/, 'changes the process trust store'],
  [/globalAgent/, 'changes the global network agent'],
  [/setGlobalDispatcher/, 'changes the global network dispatcher'],
  [/from 'node:tls'|require\('node:tls'\)/, 'reaches into the TLS layer'],
  [/process\.env\s*\[[^\]]*\]\s*=|process\.env\.\w+\s*=/, 'writes to the process environment'],
]

for (const [pattern, why] of forbidden) {
  test(`no source file ${why}`, () => {
    const offenders = sources.filter((s) => pattern.test(s.text)).map((s) => path.basename(s.file))
    assert.deepEqual(offenders, [])
  })
}

test('a whole call cycle writes no request or response content anywhere', async () => {
  const written: string[] = []
  const stub = await startStub((req, res) => {
    if (req.path === '/api/v1/auth/token') return token(res, 'tok-1')
    if (req.path === '/api/v1/fails') {
      return fail(res, 409, {
        code: 'EGN-025',
        message: 'wrong state',
        description: 'change the state first',
      })
    }
    ok(res, { key: SECRET_MARKER })
  })

  const outWrite = process.stdout.write.bind(process.stdout)
  const errWrite = process.stderr.write.bind(process.stderr)
  const capture =
    (): typeof process.stdout.write =>
    ((chunk: string | Uint8Array): boolean => {
      written.push(typeof chunk === 'string' ? chunk : new TextDecoder().decode(chunk))
      return true
    }) as typeof process.stdout.write

  process.stdout.write = capture()
  process.stderr.write = capture()
  try {
    const api = requesterOf(clientWith({ baseUrl: stub.baseUrl, ...CREDENTIAL }, {}))
    await api.json({ method: 'POST', path: '/api/v1/vault/keys', body: { secret: SECRET_MARKER } })
    await api.json({ method: 'GET', path: '/api/v1/fails' }).catch(() => undefined)
  } finally {
    process.stdout.write = outWrite
    process.stderr.write = errWrite
    await stub.close()
  }

  // The test runner writes its own progress to these streams, so the check is
  // that nothing SENSITIVE reached them: no payload, no token, no secret.
  const all = written.join('')
  assert.equal(all.includes(SECRET_MARKER), false, 'a payload reached an output stream')
  assert.equal(all.includes('tok-1'), false, 'an access token reached an output stream')
  assert.equal(all.includes(CREDENTIAL.clientSecret), false, 'the client secret reached an output stream')
  assert.equal(all.includes('wrong state'), false, 'a failure message reached an output stream')
})

/** Everything a caller could reasonably print when it catches a failure. */
function textOf(error: unknown, depth = 0): string {
  if (depth > 5 || !(error instanceof Error)) return String(error)
  const extra = error as { description?: unknown; details?: unknown; cause?: unknown }
  return [
    error.name,
    error.message,
    error.stack ?? '',
    String(extra.description ?? ''),
    JSON.stringify(extra.details ?? {}),
    extra.cause === undefined ? '' : textOf(extra.cause, depth + 1),
  ].join(' ')
}

test('a response the SDK cannot read never carries the body into the failure', async () => {
  // The runtime puts the FIRST few characters of the offending text into its own
  // parse error, so the marker is at the very start of the body: a marker further
  // in would be truncated away and the test would pass while the leak remained.
  // Attaching that error as a cause would copy response content into something a
  // caller is very likely to log, which is the one thing this SDK must not do.
  const stub = await startStub((req, res) => {
    if (req.path === '/api/v1/auth/token') return token(res, 'tok-1')
    res.setHeader('content-type', 'text/html')
    res.statusCode = 200
    res.end(`${LEAK_MARKER}{not json at all`)
  })
  try {
    const api = requesterOf(clientWith({ baseUrl: stub.baseUrl, ...CREDENTIAL }, {}))
    await assert.rejects(
      api.json({ method: 'GET', path: '/api/v1/vault/keys' }),
      (error: unknown) => {
        assert.equal(
          textOf(error).includes(LEAK_MARKER),
          false,
          'the response body reached the failure a caller will log',
        )
        return true
      },
    )
  } finally {
    await stub.close()
  }
})

test('an advisory carries only what qshield said, never the payload', async () => {
  const seen: string[] = []
  const stub = await startStub((req, res) => {
    if (req.path === '/api/v1/auth/token') return token(res, 'tok-1')
    ok(res, { key: SECRET_MARKER }, { warnings: ['the agent was offline'] })
  })
  try {
    const api = requesterOf(
      clientWith({ baseUrl: stub.baseUrl, ...CREDENTIAL, onWarning: (w) => seen.push(w) }, {}),
    )
    await api.json({ method: 'GET', path: '/api/v1/vault/keys' })
    assert.deepEqual(seen, ['the agent was offline'])
    assert.equal(seen.join('').includes(SECRET_MARKER), false)
  } finally {
    await stub.close()
  }
})

test('nothing but the configured address is ever contacted', () => {
  // Every request the SDK makes is built from the configured address. A literal
  // host anywhere in the source would be a second destination, which an
  // air-gapped deployment could never reach and no customer ever asked for.
  const offenders = sources
    .filter((s) => /https?:\/\/(?!\/)[a-z0-9.-]+/i.test(s.text.replace(/https?:\/\/qshield\.example\.com/g, '')))
    .map((s) => path.basename(s.file))
  assert.deepEqual(offenders, [])
})
