/**
 * The version advisory: what it says, when it says nothing, and how much it
 * costs.
 *
 * The expensive mistakes here are an advisory that fires on every ordinary
 * patch release, and a check that quietly makes a request on every call. Both
 * are tested for directly.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { clientWith, requesterOf } from '../src/client.js'
import {
  advisoryFor,
  compareReleases,
  isPublishedRelease,
  parseRelease,
} from '../src/internal/compat.js'
import type { QShieldClientOptions } from '../src/internal/config.js'
import { CREDENTIAL, ok, type Responder, startStub, type Stub, token } from './support/stub.js'

const TOKEN = '/api/v1/auth/token'
const THING = '/api/v1/vault/keys'

/** A published version, so the check is not skipped as built-from-source. */
const PUBLISHED = '0.14.0'

interface Deployment {
  readonly version?: string
  readonly min?: string
}

/**
 * A stub deployment: it reports its versions on the token exchange, exactly as
 * qshield does, and answers one product route.
 */
function deployment(server: Deployment, expiresIn = 900): Responder {
  return (req, res) => {
    if (req.path === TOKEN) {
      return token(res, 'tok-1', expiresIn, {
        qshield_version: server.version,
        min_sdk_version: server.min,
      })
    }
    return ok(res, { id: 'k1' })
  }
}

function clientFor(
  stub: Stub,
  seen: string[],
  extra: Partial<QShieldClientOptions> = {},
  sdkVersion: string = PUBLISHED,
) {
  return requesterOf(
    clientWith(
      { baseUrl: stub.baseUrl, ...CREDENTIAL, onWarning: (w) => seen.push(w), ...extra },
      { sdkVersion },
    ),
  )
}

function callsTo(stub: Stub, path: string): number {
  return stub.requests.filter((r) => r.path === path).length
}

/* -------------------------------------------------------------------------- */
/* The comparison, on its own                                                  */
/* -------------------------------------------------------------------------- */

test('parseRelease reads the shapes qshield actually produces', () => {
  assert.deepEqual(parseRelease('0.14.0'), { major: 0, minor: 14, patch: 0 })
  assert.deepEqual(parseRelease('v0.14.0'), { major: 0, minor: 14, patch: 0 })
  assert.deepEqual(parseRelease('V0.14.0'), { major: 0, minor: 14, patch: 0 })
  assert.deepEqual(parseRelease('  v1.2.3  '), { major: 1, minor: 2, patch: 3 })
  assert.deepEqual(parseRelease('v0.14.0-dev1'), { major: 0, minor: 14, patch: 0 })
  assert.deepEqual(parseRelease('v0.14.0-nxoslab.1'), { major: 0, minor: 14, patch: 0 })
  assert.deepEqual(parseRelease('v0.14.0-3-gabc1234-dirty'), { major: 0, minor: 14, patch: 0 })
  assert.deepEqual(parseRelease('1.2.3+build.5'), { major: 1, minor: 2, patch: 3 })
})

test('parseRelease reports anything else as unknown', () => {
  for (const bad of ['dev', 'unknown', '', '   ', '0.14', '1.2.3.4', 'v', 'x.y.z', '01.a.3']) {
    assert.equal(parseRelease(bad), undefined, `expected ${JSON.stringify(bad)} to be unknown`)
  }
  assert.equal(parseRelease(undefined), undefined)
})

test('compareReleases orders by major, then minor, then patch', () => {
  const r = (m: number, n: number, p: number) => ({ major: m, minor: n, patch: p })
  assert.ok(compareReleases(r(1, 0, 0), r(0, 99, 99)) > 0)
  assert.ok(compareReleases(r(0, 2, 0), r(0, 10, 0)) < 0)
  assert.ok(compareReleases(r(0, 1, 2), r(0, 1, 10)) < 0)
  assert.equal(compareReleases(r(1, 2, 3), r(1, 2, 3)), 0)
})

test('advisoryFor says nothing when the versions are in range', () => {
  assert.equal(advisoryFor({ qshieldVersion: '0.14.0', minSdkVersion: '0.10.0' }, '0.12.0'), undefined)
  assert.equal(advisoryFor({ qshieldVersion: '0.14.0', minSdkVersion: '0.10.0' }, '0.10.0'), undefined)
  assert.equal(advisoryFor({ qshieldVersion: '0.14.0', minSdkVersion: '0.10.0' }, '0.14.0'), undefined)
})

test('advisoryFor names both versions when this library is below the floor', () => {
  const advisory = advisoryFor({ qshieldVersion: '0.14.0', minSdkVersion: '0.10.0' }, '0.9.9')
  assert.ok(advisory !== undefined)
  assert.match(advisory, /0\.9\.9/)
  assert.match(advisory, /0\.10\.0/)
  assert.match(advisory, /Upgrade/)
})

test('advisoryFor names both versions when this library is newer than qshield', () => {
  const advisory = advisoryFor({ qshieldVersion: '0.14.0', minSdkVersion: '0.1.0' }, '0.20.0')
  assert.ok(advisory !== undefined)
  assert.match(advisory, /0\.20\.0/)
  assert.match(advisory, /0\.14\.0/)
  assert.match(advisory, /newer than the deployment/)
})

test('advisoryFor is silent when either side cannot be read', () => {
  // An unstamped deployment, which is what a local build reports.
  assert.equal(advisoryFor({ qshieldVersion: 'dev', minSdkVersion: '0.10.0' }, '0.1.0'), undefined)
  // A deployment too old to carry the floor at all.
  assert.equal(advisoryFor({ qshieldVersion: '0.14.0', minSdkVersion: undefined }, '0.1.0'), undefined)
  // This library built from source.
  assert.equal(
    advisoryFor({ qshieldVersion: '0.14.0', minSdkVersion: '9.9.9' }, '0.0.0-development'),
    undefined,
  )
  // Any unpublished build of this library, not only the checked-in placeholder.
  assert.equal(advisoryFor({ qshieldVersion: '0.14.0', minSdkVersion: '9.9.9' }, '0.1.0-rc.1'), undefined)
})

test('advisoryFor compares a leading v and a prerelease suffix on either side', () => {
  // A prerelease of the floor is the floor, not something older than it.
  assert.equal(
    advisoryFor({ qshieldVersion: 'v0.14.0-dev1', minSdkVersion: 'v0.10.0-rc.1' }, 'v0.10.0'),
    undefined,
  )
  // A prerelease of this library is still that release, not the one before it.
  assert.equal(
    advisoryFor({ qshieldVersion: 'v0.14.0', minSdkVersion: '0.10.0' }, '0.10.0-rc.1'),
    undefined,
  )
  // And the two directions still fire through the suffixes on the other side.
  assert.ok(
    advisoryFor({ qshieldVersion: 'v0.14.0-dev1', minSdkVersion: 'v0.10.0' }, 'v0.9.0') !== undefined,
  )
  assert.ok(
    advisoryFor({ qshieldVersion: 'v0.14.0-dev1', minSdkVersion: 'v0.1.0' }, 'v0.15.0') !== undefined,
  )
})

test('the suffix rule is one-sided, and deliberately so', () => {
  // A prerelease of this library is never published, so there is nothing to
  // advise about and the check stays silent.
  assert.equal(isPublishedRelease('0.1.0-rc.1'), false)
  assert.equal(isPublishedRelease('0.0.0-development'), false)
  assert.equal(advisoryFor({ qshieldVersion: '0.14.0', minSdkVersion: '9.9.9' }, '0.1.0-rc.1'), undefined)

  // A prerelease of qshield is a real deployment, so its suffix is stripped and
  // it is compared as its own release.
  assert.equal(isPublishedRelease('v0.14.0'), true)
  assert.ok(advisoryFor({ qshieldVersion: '0.14.0-dev1', minSdkVersion: '9.9.9' }, '0.1.0') !== undefined)
})

/* -------------------------------------------------------------------------- */
/* The check, against a deployment                                             */
/* -------------------------------------------------------------------------- */

test('a library below the floor is warned once, however many calls it makes', async (t) => {
  const stub = await startStub(deployment({ version: '0.20.0', min: '0.18.0' }))
  t.after(() => stub.close())

  const seen: string[] = []
  const requester = clientFor(stub, seen, {}, '0.9.0')
  await requester.json({ method: 'GET', path: THING })
  await requester.json({ method: 'GET', path: THING })
  await requester.json({ method: 'GET', path: THING })

  assert.equal(seen.length, 1)
  assert.match(seen[0] ?? '', /0\.9\.0/)
  assert.match(seen[0] ?? '', /0\.18\.0/)
  assert.equal(callsTo(stub, THING), 3)
})

test('a library newer than the deployment is warned once', async (t) => {
  const stub = await startStub(deployment({ version: '0.14.0', min: '0.1.0' }))
  t.after(() => stub.close())

  const seen: string[] = []
  const requester = clientFor(stub, seen, {}, '0.20.0')
  await requester.json({ method: 'GET', path: THING })
  await requester.json({ method: 'GET', path: THING })

  assert.equal(seen.length, 1)
  assert.match(seen[0] ?? '', /newer than the deployment/)
})

test('a version in range says nothing', async (t) => {
  const stub = await startStub(deployment({ version: '0.14.0', min: '0.10.0' }))
  t.after(() => stub.close())

  const seen: string[] = []
  const requester = clientFor(stub, seen, {}, '0.12.0')
  await requester.json({ method: 'GET', path: THING })

  assert.deepEqual(seen, [])
})

test('THE ADVISORY COSTS NO REQUEST OF ITS OWN', async (t) => {
  const stub = await startStub(deployment({ version: '0.14.0', min: '0.18.0' }))
  t.after(() => stub.close())

  const seen: string[] = []
  const requester = clientFor(stub, seen, {}, '0.9.0')
  await Promise.all([
    requester.json({ method: 'GET', path: THING }),
    requester.json({ method: 'GET', path: THING }),
    requester.json({ method: 'GET', path: THING }),
  ])
  await requester.json({ method: 'GET', path: THING })

  // One exchange for the credential and four product calls. Nothing else: the
  // versions rode back on the exchange the library had to make anyway.
  assert.equal(callsTo(stub, TOKEN), 1)
  assert.equal(callsTo(stub, THING), 4)
  assert.equal(stub.requests.length, 5)
  assert.equal(seen.length, 1)
})

test('with the check off nothing is said, and nothing extra is asked', async (t) => {
  const stub = await startStub(deployment({ version: '0.14.0', min: '9.9.9' }))
  t.after(() => stub.close())

  const seen: string[] = []
  const requester = clientFor(stub, seen, { versionCheck: 'off' }, '0.1.0')
  await requester.json({ method: 'GET', path: THING })
  await requester.json({ method: 'GET', path: THING })

  assert.deepEqual(seen, [])
  assert.equal(stub.requests.length, 3)
})

test('a deployment that says nothing about versions is silent', async (t) => {
  const stub = await startStub((req, res) => {
    if (req.path === TOKEN) return token(res, 'tok-1')
    return ok(res, { id: 'k1' })
  })
  t.after(() => stub.close())

  const seen: string[] = []
  const requester = clientFor(stub, seen, {}, '0.1.0')
  const answer = await requester.json<{ id: string }>({ method: 'GET', path: THING })

  assert.deepEqual(answer.data, { id: 'k1' })
  assert.deepEqual(seen, [])
})

test('an unstamped deployment is silent', async (t) => {
  const stub = await startStub(deployment({ version: 'dev', min: '9.9.9' }))
  t.after(() => stub.close())

  const seen: string[] = []
  const requester = clientFor(stub, seen, {}, '0.1.0')
  await requester.json({ method: 'GET', path: THING })

  assert.deepEqual(seen, [])
})

test('a library that was never published is silent whatever the deployment says', async (t) => {
  const stub = await startStub(deployment({ version: '0.14.0', min: '9.9.9' }))
  t.after(() => stub.close())

  const seen: string[] = []
  const requester = clientFor(stub, seen, {}, '0.0.0-development')
  await requester.json({ method: 'GET', path: THING })

  assert.deepEqual(seen, [])
})

test('a download route is covered too, because the exchange is shared', async (t) => {
  const stub = await startStub((req, res) => {
    if (req.path === TOKEN) {
      return token(res, 'tok-1', 900, { qshield_version: '0.14.0', min_sdk_version: '0.18.0' })
    }
    res.writeHead(200, { 'content-type': 'application/x-pem-file' })
    res.end('-----BEGIN CERTIFICATE-----')
  })
  t.after(() => stub.close())

  const seen: string[] = []
  const requester = clientFor(stub, seen, {}, '0.9.0')
  const pem = '/api/v1/com/pki/x/download'
  await requester.bytes({ method: 'GET', path: pem }, 'application/x-pem-file')
  await requester.bytes({ method: 'GET', path: pem }, 'application/x-pem-file')

  assert.equal(seen.length, 1)
})

test('a deployment upgraded under a running client is noticed on the next exchange', async (t) => {
  // A stable mismatch is said once; a CHANGED one is said again. The clock is
  // driven forward so the token expires and the library re-mints, which is the
  // only moment it can learn that the deployment moved.
  let exchanges = 0
  const stub = await startStub((req, res) => {
    if (req.path === TOKEN) {
      exchanges += 1
      return token(res, `tok-${exchanges}`, 900, {
        qshield_version: exchanges === 1 ? '0.14.0' : '0.30.0',
        min_sdk_version: exchanges === 1 ? '0.10.0' : '0.25.0',
      })
    }
    return ok(res, { id: 'k1' })
  })
  t.after(() => stub.close())

  const seen: string[] = []
  let clock = 1_000_000
  const requester = requesterOf(
    clientWith(
      { baseUrl: stub.baseUrl, ...CREDENTIAL, onWarning: (w) => seen.push(w) },
      { now: () => clock, sdkVersion: '0.12.0' },
    ),
  )

  await requester.json({ method: 'GET', path: THING })
  assert.deepEqual(seen, [], 'in range against the first deployment')

  clock += 15 * 60 * 1000
  await requester.json({ method: 'GET', path: THING })

  assert.equal(exchanges, 2, 'the expired token was re-minted')
  assert.equal(seen.length, 1, 'the upgraded deployment left the library below the floor')
  assert.match(seen[0] ?? '', /0\.25\.0/)
})
