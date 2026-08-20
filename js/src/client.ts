/**
 * The client a customer constructs.
 *
 * At this phase it holds the transport and nothing else: the product namespaces
 * (vault keys, certificates) are added on top of it in later phases, each as its
 * own property, so they can never collide with one another.
 *
 * The transport itself is not reachable from the client. A caller gets typed
 * methods and typed failures; they never get a request, a response, a header or
 * a status code. That is what lets the conversation with qshield change without
 * breaking anyone's code.
 */

import { advisoryFor } from './internal/compat.js'
import { type QShieldClientOptions, resolveConfig } from './internal/config.js'
import { fetchTransport, type Transport } from './internal/http.js'
import { Requester } from './internal/requester.js'
import { TokenSource } from './internal/token.js'
import { SDK_VERSION } from './internal/version.js'
import { VaultNamespace } from './vault/index.js'

/** What the client is built from. Substituted in tests, never by a customer. */
export interface Wiring {
  readonly transport: Transport
  readonly now: () => number
  /**
   * The version this library reports of itself in the compatibility check. The
   * real value is written into the source by the release workflow, so a test
   * cannot reach a published one and supplies its own instead.
   */
  readonly sdkVersion: string
}

const wiringDefaults: Wiring = {
  transport: fetchTransport,
  now: Date.now,
  sdkVersion: SDK_VERSION,
}

/**
 * The transport behind each client.
 *
 * Held outside the class so that it forms no part of the published type. A
 * property, even a private one, shows up in the declaration file and becomes
 * something consumers can see and eventually depend on.
 */
const requesters = new WeakMap<QShieldClient, Requester>()

/** A connection to one qshield deployment, authenticated as a service account. */
export class QShieldClient {
  /** QuantumVault: the keys in your workspace. */
  declare readonly vault: VaultNamespace

  constructor(options: QShieldClientOptions) {
    build(this, options, wiringDefaults)
  }
}

/** Builds a client with substituted wiring. For the SDK's own tests only. */
export function clientWith(options: QShieldClientOptions, wiring: Partial<Wiring>): QShieldClient {
  const client = Object.create(QShieldClient.prototype) as QShieldClient
  build(client, options, { ...wiringDefaults, ...wiring })
  return client
}

/** The transport for a client, for the namespaces built on top of it. */
export function requesterOf(client: QShieldClient): Requester {
  const requester = requesters.get(client)
  if (requester === undefined) {
    throw new TypeError('this object was not created by the qshield SDK')
  }
  return requester
}

function build(client: QShieldClient, options: QShieldClientOptions, wiring: Wiring): void {
  const config = resolveConfig(options)
  const tokens = new TokenSource(config, wiring.transport, wiring.now)

  if (config.versionCheck === 'warn') {
    // The versions arrive with the credential exchange, which has to happen
    // before anything else, so the advisory costs nothing and needs no state
    // machine of its own. It is repeated only when it CHANGES, so a stable
    // mismatch is said once while a deployment upgraded under a long-running
    // application is still noticed.
    let said: string | undefined
    tokens.onVersions((seen) => {
      const advisory = advisoryFor(seen, wiring.sdkVersion)
      if (advisory === undefined || advisory === said) return
      said = advisory
      config.warn(advisory)
    })
  }

  const requester = new Requester(config, wiring.transport, tokens, wiring.now)
  requesters.set(client, requester)

  // Attached here rather than in the constructor because the test seam builds a
  // client with Object.create and never runs the constructor body. A namespace
  // wired in the constructor would be missing from every test client, which is
  // the sort of difference that makes a suite prove the wrong thing.
  Object.defineProperty(client, 'vault', {
    value: new VaultNamespace(requester),
    enumerable: true,
  })
}
