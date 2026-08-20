/**
 * One authenticated call to qshield, from start to finish.
 *
 * This is where the pieces meet: obtain the token, address the request, send it,
 * decide whether a failure is worth repeating, and hand back either the payload
 * or a typed failure.
 *
 * Two rules here are security properties rather than style. NO REQUEST OR
 * RESPONSE CONTENT IS EVER LOGGED, by any path, at any level - bodies carry key
 * material, private keys and secrets, and there is no flag that turns logging
 * on. And NO REQUEST GOES ANYWHERE BUT THE CONFIGURED ADDRESS - no telemetry, no
 * registry check, no update ping - because an air-gapped deployment is a
 * first-class customer, not an edge case.
 */

import type { ResolvedConfig } from './config.js'
import { type ApiResult, errorFrom, successFrom } from './envelope.js'
import { RequestCancelled } from './codes.js'
import { CancelledError, fromEntry, RateLimitError } from './errors.js'
import { type HttpResponse, type Transport, TransportError } from './http.js'
import {
  backoffMs,
  MAX_ATTEMPTS,
  retryAfterHeaderOf,
  retryAfterMs,
  retryAfterMsFrom,
  sleep,
} from './retry.js'
import type { TokenSource } from './token.js'

/** What a domain namespace asks for. */
export interface RequestSpec {
  readonly method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  /** The route, beginning with a slash, without the address. */
  readonly path: string
  /** Query parameters. Anything undefined is left off. */
  readonly query?: Readonly<Record<string, string | number | boolean | undefined>>
  /** The request payload, sent as JSON. */
  readonly body?: unknown
  /** The caller's cancellation signal. */
  readonly signal?: AbortSignal | undefined
}

/** A response that is bytes rather than a payload, such as a certificate file. */
export interface BytesResult {
  readonly bytes: Uint8Array
  readonly contentType: string
  /** The filename qshield suggested, when it suggested one. */
  readonly filename: string | undefined
  readonly requestId: string | undefined
}

/** Makes authenticated calls. Not exported from the package. */
export class Requester {
  readonly #config: ResolvedConfig
  readonly #transport: Transport
  readonly #tokens: TokenSource
  readonly #now: () => number

  constructor(
    config: ResolvedConfig,
    transport: Transport,
    tokens: TokenSource,
    now: () => number = Date.now,
  ) {
    this.#config = config
    this.#transport = transport
    this.#tokens = tokens
    this.#now = now
  }

  /** A call that answers with the platform envelope. */
  async json<T>(spec: RequestSpec): Promise<ApiResult<T>> {
    const response = await this.#send(spec, 'application/json')
    if (response.status >= 400) throw errorFrom(response.status, response.headers, response.body)
    return successFrom<T>(response.status, response.headers, response.body, this.#config.warn)
  }

  /** A call that answers with raw bytes, such as a certificate download. */
  async bytes(spec: RequestSpec, accept: string): Promise<BytesResult> {
    const response = await this.#send(spec, accept)
    // A failure on a download route still answers in the envelope, so it is read
    // the same way as any other failure.
    if (response.status >= 400) throw errorFrom(response.status, response.headers, response.body)
    return {
      bytes: response.body,
      contentType: response.headers.get('content-type') ?? '',
      filename: filenameFrom(response.headers.get('content-disposition')),
      requestId: response.headers.get('x-request-id') ?? undefined,
    }
  }

  /**
   * Sends one call, with the narrow retry policy applied and at most one token
   * renewal.
   *
   * The renewal is guarded by a flag on this call alone, so a token qshield
   * keeps refusing produces one clear failure rather than a loop.
   */
  async #send(spec: RequestSpec, accept: string): Promise<HttpResponse> {
    const url = this.#url(spec)
    const payload = spec.body === undefined ? undefined : JSON.stringify(spec.body)
    let renewed = false

    for (let attempt = 1; ; attempt += 1) {
      this.#throwIfCancelled(spec.signal)

      let token: string
      try {
        token = await this.#tokens.get(spec.signal)
      } catch (error) {
        // A connection that was never established is worth one more attempt on
        // the token route for the same reason as on any other: nothing can have
        // happened, so nothing can happen twice.
        if (error instanceof TransportError) {
          const { failure } = error
          if (failure.repeatable && attempt < MAX_ATTEMPTS) {
            await sleep(backoffMs(attempt, undefined), spec.signal)
            continue
          }
          throw failure.error
        }
        // The token route carries its own rate limit, shared by every process
        // behind one network address. A refusal there is worth waiting out, and
        // asking for a token again is safe: it creates nothing and changes
        // nothing. This is the one route where the customer's whole estate
        // shares a bucket, so what the server said about coming back is
        // honoured rather than guessed at.
        if (error instanceof RateLimitError && attempt < MAX_ATTEMPTS) {
          const after = retryAfterMsFrom(retryAfterHeaderOf(error), this.#now())
          await sleep(backoffMs(attempt, after), spec.signal)
          continue
        }
        throw error
      }
      let response: HttpResponse
      try {
        response = await this.#transport({
          method: spec.method,
          url,
          headers: {
            authorization: `Bearer ${token}`,
            accept,
            ...(payload === undefined ? {} : { 'content-type': 'application/json' }),
          },
          ...(payload === undefined ? {} : { body: payload }),
          signal: spec.signal,
          timeoutMs: this.#config.timeoutMs,
        })
      } catch (error) {
        if (!(error instanceof TransportError)) throw error
        const { failure } = error
        if (failure.repeatable && attempt < MAX_ATTEMPTS) {
          await sleep(backoffMs(attempt, undefined), spec.signal)
          continue
        }
        throw failure.error
      }

      if (response.status === 401 && !renewed) {
        // The token was refused mid-life. Replace it once and repeat this one
        // call once. A second refusal is the answer.
        renewed = true
        this.#tokens.invalidate(token)
        continue
      }

      if (response.status === 429 && attempt < MAX_ATTEMPTS) {
        const after = retryAfterMs(response.headers, this.#now())
        await sleep(backoffMs(attempt, after), spec.signal)
        continue
      }

      return response
    }
  }

  #url(spec: RequestSpec): string {
    const url = new URL(`${this.#config.baseUrl}${spec.path}`)
    for (const [key, value] of Object.entries(spec.query ?? {})) {
      if (value !== undefined) url.searchParams.set(key, String(value))
    }
    return url.toString()
  }

  #throwIfCancelled(signal: AbortSignal | undefined): void {
    if (signal?.aborted !== true) return
    throw fromEntry(CancelledError, RequestCancelled)
  }
}

/**
 * Reads the suggested filename off a content disposition header.
 *
 * A header that does not decode is not worth failing a download over: the bytes
 * are the answer and the filename is a suggestion. A stray percent sign in the
 * name would otherwise raise a decoding error from outside the SDK's own set of
 * failures, which is exactly what a caller cannot be asked to handle.
 */
function filenameFrom(header: string | null): string | undefined {
  if (header === null) return undefined
  const match = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(header)
  if (match === null) return undefined
  const value = match[1]
  if (value === undefined || value === '') return undefined
  try {
    return decodeURIComponent(value)
  } catch {
    return value
  }
}
