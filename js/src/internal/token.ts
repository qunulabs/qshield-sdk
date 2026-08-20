/**
 * Getting and holding the access token.
 *
 * The exchange is the standard client-credentials grant. It is deliberately not
 * in the platform envelope, so that an off-the-shelf OAuth client works against
 * it, which means this is the one place in the SDK that reads a different
 * response shape. One exception inside the exception: the rate-limit refusal on
 * this route does arrive in the platform envelope, so both shapes are handled.
 *
 * There is no refresh token. Renewing means presenting the credential again.
 *
 * The exchange also carries the two versions the compatibility advisory needs.
 * They ride here rather than on a route of their own because a token has to be
 * obtained before anything else can happen, so the answer arrives without the
 * library ever spending a request on the question - and it is refreshed on every
 * renewal, so a deployment upgraded underneath a long-running process is seen.
 *
 * Concurrent callers share ONE exchange. This is correctness, not tidiness: the
 * token route allows ten requests a second per network address, and a customer
 * whose estate sits behind one address shares that allowance across every
 * process they run. A burst of calls that each minted their own token would
 * rate-limit the customer against themselves.
 */

import { RequestCancelled, ResponseNotUnderstood } from './codes.js'
import { errorFrom, parseJson, requestIdOf } from './envelope.js'
import {
  AuthenticationError,
  CancelledError,
  classify,
  fromEntry,
  ProtocolError,
  QShieldError,
  type QShieldErrorFields,
} from './errors.js'
import type { ResolvedConfig } from './config.js'
import type { HttpResponse, Transport } from './http.js'

/** The route the credential is exchanged at. */
export const TOKEN_PATH = '/api/v1/auth/token'

/**
 * How long before expiry the token is replaced. Fifteen minutes is the default
 * life, so a minute of headroom covers a slow request without renewing so often
 * that the allowance is wasted.
 */
const RENEW_MARGIN_MS = 60_000

interface Token {
  readonly value: string
  readonly expiresAt: number
}

/**
 * What the exchange said about versions.
 *
 * Both are optional on the wire. A deployment that predates them, or one built
 * without a version stamp, simply does not say, and the advisory stays silent
 * rather than guessing.
 */
export interface VersionsSeen {
  readonly qshieldVersion: string | undefined
  readonly minSdkVersion: string | undefined
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** Holds one credential's token and hands it out. */
export class TokenSource {
  readonly #config: ResolvedConfig
  readonly #transport: Transport
  readonly #now: () => number
  #token: Token | undefined
  #pending: Promise<Token> | undefined
  #versions: VersionsSeen | undefined
  #onVersions: ((seen: VersionsSeen) => void) | undefined

  constructor(config: ResolvedConfig, transport: Transport, now: () => number = Date.now) {
    this.#config = config
    this.#transport = transport
    this.#now = now
  }

  /**
   * Registers what to do with the versions an exchange reports.
   *
   * Called with the versions from every exchange, including renewals, so a
   * deployment that changes under a long-lived client is noticed. The callback
   * decides whether that is worth saying anything about.
   */
  onVersions(handler: (seen: VersionsSeen) => void): void {
    this.#onVersions = handler
    if (this.#versions !== undefined) handler(this.#versions)
  }

  /**
   * The token to send, obtaining or renewing one only when needed.
   *
   * A caller waits for the shared exchange but does not own it. Cancelling here
   * stops THIS caller waiting and nothing else: the exchange belongs to every
   * caller at once, and letting whichever one happened to start it abort the
   * others would fail calls that were never cancelled.
   */
  async get(signal?: AbortSignal): Promise<string> {
    const held = this.#token
    if (held !== undefined && held.expiresAt - RENEW_MARGIN_MS > this.#now()) {
      return held.value
    }
    return (await waitFor(this.#exchangeOnce(), signal)).value
  }

  /**
   * Discards a token qshield has just refused, so the next call obtains a new
   * one. Takes the refused value so that a token already replaced by another
   * caller is not thrown away as well.
   */
  invalidate(refused: string): void {
    if (this.#token?.value === refused) this.#token = undefined
  }

  /**
   * One exchange at a time, however many callers are waiting.
   *
   * It carries no caller's cancellation signal, because it is not any one
   * caller's request. The per-attempt timeout still bounds it.
   */
  #exchangeOnce(): Promise<Token> {
    const inFlight = this.#pending
    if (inFlight !== undefined) return inFlight

    const started = this.#exchange()
      .then((token) => {
        this.#token = token
        return token
      })
      .finally(() => {
        this.#pending = undefined
      })

    this.#pending = started
    return started
  }

  async #exchange(): Promise<Token> {
    const body = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: this.#config.clientId,
      client_secret: this.#config.clientSecret,
    }).toString()

    const requestedAt = this.#now()
    // A transport failure travels out of here untouched, with its retry verdict
    // intact, so the retry layer applies the same rule to a token exchange as to
    // any other call. Unwrapping it to a plain failure would quietly deny a cold
    // client the one repeat a never-established connection has always been
    // allowed.
    const response: HttpResponse = await this.#transport({
      method: 'POST',
      url: `${this.#config.baseUrl}${TOKEN_PATH}`,
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        accept: 'application/json',
      },
      body,
      timeoutMs: this.#config.timeoutMs,
    })

    if (response.status !== 200) throw tokenFailure(response)

    const parsed = parseJson(response.body)
    if (!isRecord(parsed)) throw fromEntry(ProtocolError, ResponseNotUnderstood)

    const accessToken = parsed['access_token']
    const expiresIn = parsed['expires_in']
    if (typeof accessToken !== 'string' || accessToken === '' || typeof expiresIn !== 'number') {
      throw fromEntry(ProtocolError, ResponseNotUnderstood, {
        details: { field: 'access_token' },
      })
    }

    const seen: VersionsSeen = {
      qshieldVersion: stringOrUndefined(parsed['qshield_version']),
      minSdkVersion: stringOrUndefined(parsed['min_sdk_version']),
    }
    this.#versions = seen
    this.#onVersions?.(seen)

    return { value: accessToken, expiresAt: requestedAt + expiresIn * 1000 }
  }
}

/** Reads an optional string field, treating anything else as absent. */
function stringOrUndefined(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '' ? value : undefined
}

/**
 * Waits for the shared exchange on behalf of one caller.
 *
 * The caller's signal ends only this wait. The exchange itself runs on, because
 * other callers are waiting for the same one and none of them asked to stop.
 */
async function waitFor(shared: Promise<Token>, signal?: AbortSignal): Promise<Token> {
  if (signal === undefined) return await shared
  if (signal.aborted) throw fromEntry(CancelledError, RequestCancelled)

  return await new Promise<Token>((resolve, reject) => {
    const onAbort = (): void => {
      reject(fromEntry(CancelledError, RequestCancelled))
    }
    signal.addEventListener('abort', onAbort, { once: true })
    shared.then(resolve, reject).finally(() => {
      signal.removeEventListener('abort', onAbort)
    })
  })
}

/**
 * Turns a refused exchange into a failure.
 *
 * Two shapes arrive on this one route. The flat one is the grant's own, and now
 * carries the qshield code alongside the standard fields. The enveloped one is
 * the rate-limit refusal, which is applied before the handler runs and so speaks
 * the platform shape.
 */
function tokenFailure(response: HttpResponse): QShieldError {
  let parsed: unknown
  try {
    parsed = parseJson(response.body)
  } catch {
    parsed = undefined
  }

  // The enveloped shape: error is an object.
  if (isRecord(parsed) && isRecord(parsed['error'])) {
    return errorFrom(response.status, response.headers, response.body)
  }

  // The flat shape: error is the grant's own short string.
  if (isRecord(parsed) && typeof parsed['error'] === 'string') {
    const code = typeof parsed['error_code'] === 'string' ? parsed['error_code'] : ''
    const description =
      typeof parsed['error_description'] === 'string' ? parsed['error_description'] : ''
    const fields: QShieldErrorFields = {
      code,
      message: description,
      description,
      details: Object.freeze({ oauth_error: parsed['error'] }),
      requestId: requestIdOf(response.headers, parsed),
      status: response.status,
    }
    return new (classify(code, response.status))(fields)
  }

  const entry = ResponseNotUnderstood
  return new AuthenticationError({
    code: entry.code,
    message: entry.operator,
    description: entry.developer,
    details: Object.freeze({ status: String(response.status) }),
    requestId: requestIdOf(response.headers, parsed),
    status: response.status,
  })
}
