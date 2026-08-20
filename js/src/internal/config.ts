/**
 * Client configuration: what a caller passes in, and what the rest of the SDK
 * gets to work with.
 *
 * Everything is settled once, here, at construction. A malformed address or an
 * obviously wrong credential fails before a single request leaves the process,
 * naming which value is at fault - rather than surfacing later as an
 * unauthorised response that looks like a server problem.
 *
 * There is deliberately no certificate authority option, no proxy option and no
 * way to relax certificate verification. Connectivity and trust belong to the
 * machine and the application that hosts this SDK, and a library has no business
 * changing either.
 */

import { ClientConfigurationInvalid } from './codes.js'
import { ConfigurationError, fromEntry } from './errors.js'

/** How the SDK reports something non-fatal. */
export type WarningHandler = (warning: string) => void

/** What a caller passes to the client constructor. */
export interface QShieldClientOptions {
  /**
   * The qshield address, for example `https://qshield.example.com`. Must be
   * https, except on the local machine where http is allowed for development.
   */
  readonly baseUrl: string
  /** The service account client id, beginning `qsc_`. */
  readonly clientId: string
  /** The service account client secret, beginning `qss_`. Keep it secret. */
  readonly clientSecret: string
  /**
   * How long to wait for one response, in milliseconds. Applies to each
   * attempt, not to a whole sequence of them. Defaults to 30 seconds.
   */
  readonly timeoutMs?: number
  /**
   * Where non-fatal advisories go: notes qshield attaches to a successful
   * response, and the version advisory. Defaults to the process warning
   * channel. Pass your own to route them into your application's log.
   */
  readonly onWarning?: WarningHandler
  /**
   * Whether to compare this library's version against the qshield it is
   * calling. `warn` (the default) sends an advisory to the warning handler when
   * the two are too far apart. `off` says nothing.
   *
   * The comparison costs no request: qshield reports both versions with the
   * credential exchange. It never fails a call, whatever it finds.
   */
  readonly versionCheck?: VersionCheck
}

/** What to do about a version difference. */
export type VersionCheck = 'warn' | 'off'

/** The settled configuration the rest of the SDK uses. */
export interface ResolvedConfig {
  readonly baseUrl: string
  readonly clientId: string
  readonly clientSecret: string
  readonly timeoutMs: number
  readonly warn: WarningHandler
  readonly versionCheck: VersionCheck
}

/** The default per-attempt response timeout. */
const DEFAULT_TIMEOUT_MS = 30_000

/** Mirrors the server's credential shape, so a typo fails here and not there. */
const CLIENT_ID_PATTERN = /^qsc_[A-Za-z0-9]{22}$/
const CLIENT_SECRET_PATTERN = /^qss_[A-Za-z0-9_-]{43}$/

/** Hosts where http is allowed, because that is what local development uses. */
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1'])

function invalid(field: string, problem: string): ConfigurationError {
  return fromEntry(ConfigurationError, ClientConfigurationInvalid, {
    details: { [field]: problem },
  }) as ConfigurationError
}

/**
 * Checks and normalises what the caller passed.
 *
 * The address keeps any path prefix it was given, since qshield can sit under
 * one behind a reverse proxy, and loses a trailing slash so that joining a
 * route onto it can never produce a doubled separator.
 */
export function resolveConfig(options: QShieldClientOptions): ResolvedConfig {
  if (typeof options.baseUrl !== 'string' || options.baseUrl.trim() === '') {
    throw invalid('baseUrl', 'required')
  }

  let parsed: URL
  try {
    parsed = new URL(options.baseUrl)
  } catch {
    throw invalid('baseUrl', 'must be an absolute URL, for example https://qshield.example.com')
  }

  const loopback = LOOPBACK_HOSTS.has(parsed.hostname)
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && loopback)) {
    throw invalid('baseUrl', 'must use https, except on the local machine')
  }
  if (parsed.username !== '' || parsed.password !== '') {
    throw invalid('baseUrl', 'must not carry credentials')
  }
  if (parsed.search !== '' || parsed.hash !== '') {
    throw invalid('baseUrl', 'must not carry a query string or a fragment')
  }

  if (typeof options.clientId !== 'string' || !CLIENT_ID_PATTERN.test(options.clientId)) {
    throw invalid('clientId', 'must be qsc_ followed by 22 letters and digits')
  }
  if (
    typeof options.clientSecret !== 'string' ||
    !CLIENT_SECRET_PATTERN.test(options.clientSecret)
  ) {
    throw invalid('clientSecret', 'must be qss_ followed by 43 characters')
  }

  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw invalid('timeoutMs', 'must be a positive number of milliseconds')
  }

  const versionCheck = options.versionCheck ?? 'warn'
  if (versionCheck !== 'warn' && versionCheck !== 'off') {
    throw invalid('versionCheck', "must be 'warn' or 'off'")
  }

  return {
    baseUrl: `${parsed.origin}${parsed.pathname.replace(/\/+$/, '')}`,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    timeoutMs,
    warn: options.onWarning ?? defaultWarn,
    versionCheck,
  }
}

/**
 * Where advisories go when the caller does not say. The process warning channel
 * is what a Node application already watches, and it carries no request or
 * response content - only the advisory text qshield sent.
 */
function defaultWarn(warning: string): void {
  process.emitWarning(warning, 'QShieldWarning')
}
