/**
 * The one place the SDK touches the network.
 *
 * Everything else in the package speaks in terms of this seam, so the runtime
 * underneath could be replaced without a single public type changing.
 *
 * It is built on the runtime's own fetch. The SDK passes no transport options
 * of any kind: no agent, no dispatcher, no certificate settings, no proxy. Trust
 * and connectivity are the host application's and the machine's, and a library
 * that reaches into either is a library that can weaken a customer's security
 * without them knowing.
 *
 * Its other job is to turn the runtime's low-level network failures into the
 * SDK's own coded errors, so a caller never meets a raw system error code.
 */

import {
  AddressUnresolvable,
  ConnectionFailed,
  RequestCancelled,
  RequestTimedOut,
  ServerCertificateUntrusted,
} from './codes.js'
import {
  CancelledError,
  ConnectionError,
  fromEntry,
  QShieldError,
  TimeoutError,
} from './errors.js'

/** One outgoing request, already fully addressed. */
export interface HttpRequest {
  readonly method: string
  readonly url: string
  readonly headers: Readonly<Record<string, string>>
  readonly body?: string | Uint8Array
  /** The caller's cancellation signal, if any. */
  readonly signal?: AbortSignal | undefined
  /** How long to wait for this one attempt. */
  readonly timeoutMs: number
}

/** One response, read in full. */
export interface HttpResponse {
  readonly status: number
  readonly headers: Headers
  readonly body: Uint8Array
}

/** A failed attempt, and what may be done about it. */
export interface TransportFailure {
  readonly error: QShieldError
  /**
   * True only when the connection was never established, so the request cannot
   * have been acted on and repeating it cannot repeat an effect. This is a
   * statement of fact about what happened, not a decision about what to do.
   */
  readonly unsent: boolean
  /**
   * Whether repeating the attempt could plausibly succeed. Never true unless
   * `unsent` is, because repeating a request that may have been carried out can
   * carry it out twice. It is separately false for a failure that will simply
   * happen again: a certificate this process does not trust will not become
   * trusted a quarter of a second later, and repeating only delays the message
   * that tells the customer how to fix it.
   */
  readonly repeatable: boolean
}

/** Raised internally so the retry layer can see the `unsent` flag. */
export class TransportError extends Error {
  readonly failure: TransportFailure

  constructor(failure: TransportFailure) {
    super(failure.error.message)
    this.name = 'TransportError'
    this.failure = failure
  }
}

/** The network seam. One implementation ships; tests substitute their own. */
export type Transport = (request: HttpRequest) => Promise<HttpResponse>

/**
 * System error codes that mean the connection was never established.
 *
 * Only these are safe to repeat. A connection that was reset, for instance, may
 * have been reset after qshield already acted on the request, so repeating it
 * could act twice.
 */
const UNSENT_CODES = new Set([
  'ECONNREFUSED',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'EAI_AGAIN',
  'UND_ERR_CONNECT_TIMEOUT',
])

/** System error codes that mean the host name could not be resolved. */
const DNS_CODES = new Set(['ENOTFOUND', 'EAI_AGAIN'])

/**
 * TLS verification failures. A certificate the process does not trust is the
 * single most likely first-run failure in a customer deployment, because Node
 * ignores the machine trust store unless it is told not to, so it gets its own
 * code and an explanation rather than being lumped in with a refused connection.
 */
const TLS_CODE_PATTERN =
  /^(?:UNABLE_TO_|SELF_SIGNED|DEPTH_ZERO_SELF_SIGNED|CERT_|ERR_TLS)/

/** Digs the underlying system error out of whatever fetch threw. */
function systemCode(error: unknown): string {
  let current: unknown = error
  for (let depth = 0; depth < 5 && current instanceof Error; depth += 1) {
    const code = (current as { code?: unknown }).code
    if (typeof code === 'string' && code !== '') return code
    current = (current as { cause?: unknown }).cause
  }
  return ''
}

/** Turns a thrown network failure into an SDK error plus its retry verdict. */
function toFailure(error: unknown, cancelled: boolean, timedOut: boolean): TransportFailure {
  if (cancelled) {
    return {
      error: fromEntry(CancelledError, RequestCancelled, { cause: error }),
      unsent: false,
      repeatable: false,
    }
  }
  if (timedOut) {
    return {
      error: fromEntry(TimeoutError, RequestTimedOut, { cause: error }),
      unsent: false,
      repeatable: false,
    }
  }

  const code = systemCode(error)
  if (TLS_CODE_PATTERN.test(code)) {
    return {
      error: fromEntry(ConnectionError, ServerCertificateUntrusted, {
        details: { cause: code },
        cause: error,
      }),
      unsent: true,
      // Nothing was sent, but nothing will change either. Repeating this only
      // makes the customer wait three times as long for the message that names
      // the fix.
      repeatable: false,
    }
  }
  if (DNS_CODES.has(code)) {
    return {
      error: fromEntry(ConnectionError, AddressUnresolvable, {
        details: { cause: code },
        cause: error,
      }),
      // A name that does not resolve at all is permanent; a temporary
      // resolver failure is worth one more attempt.
      unsent: code === 'EAI_AGAIN',
      repeatable: code === 'EAI_AGAIN',
    }
  }
  return {
    error: fromEntry(ConnectionError, ConnectionFailed, {
      details: code === '' ? {} : { cause: code },
      cause: error,
    }),
    unsent: UNSENT_CODES.has(code),
    repeatable: UNSENT_CODES.has(code),
  }
}

/**
 * The shipped transport.
 *
 * The timeout is per attempt and is enforced over the whole exchange, including
 * reading the body, so a server that accepts a request and then stalls cannot
 * hold a caller forever.
 */
export const fetchTransport: Transport = async (request) => {
  const timeout = new AbortController()
  const timer = setTimeout(() => {
    timeout.abort()
  }, request.timeoutMs)
  const signals = [timeout.signal]
  if (request.signal !== undefined) signals.push(request.signal)
  const signal = AbortSignal.any(signals)

  try {
    const response = await fetch(request.url, {
      method: request.method,
      headers: request.headers,
      ...(request.body === undefined ? {} : { body: request.body as NonNullable<RequestInit['body']> }),
      signal,
      redirect: 'error',
      cache: 'no-store',
    })
    const body = new Uint8Array(await response.arrayBuffer())
    return { status: response.status, headers: response.headers, body }
  } catch (error) {
    const cancelled = request.signal?.aborted === true
    throw new TransportError(toFailure(error, cancelled, timeout.signal.aborted && !cancelled))
  } finally {
    clearTimeout(timer)
  }
}
