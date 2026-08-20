/**
 * When a failed attempt is worth making again.
 *
 * The list is deliberately short, and short is the point. An SDK that repeats a
 * request it should not can issue a second certificate, or perform a key
 * operation twice, and the caller sees one success and never learns.
 *
 * Repeat only:
 *  - a rate-limit refusal, which says in as many words "later, not never";
 *  - a connection that was never established, so nothing can have happened.
 *
 * Never repeat anything else. In particular, never a timeout, because a request
 * that timed out may well have been carried out; never a sealed vault, because
 * unsealing is a human act that can take hours and a typed failure is more use
 * than a client that hangs; and never any other refusal, because the answer will
 * not change.
 *
 * The limits are internal on purpose. Every setting the SDK exposes is a promise
 * it has to keep for the life of the package.
 */

import { RequestCancelled } from './codes.js'
import { CancelledError, fromEntry, type QShieldError } from './errors.js'

/** Attempts in total, including the first one. */
export const MAX_ATTEMPTS = 3

/** The first wait, doubling each time. */
const BASE_DELAY_MS = 250

/** The longest single wait, so a burst cannot stall a caller for minutes. */
const MAX_DELAY_MS = 4_000

/** The longest a Retry-After value is honoured before it is treated as too long to wait. */
const MAX_HONOURED_RETRY_AFTER_MS = 30_000

/**
 * How long to wait before attempt number `attempt`, counting the first as 1.
 *
 * The jitter is not decoration. Without it, a fleet of workers refused together
 * comes back together, and the second wave is refused for the same reason as the
 * first.
 */
export function backoffMs(attempt: number, retryAfterMs: number | undefined, random = Math.random): number {
  if (retryAfterMs !== undefined && retryAfterMs >= 0) {
    return Math.min(retryAfterMs, MAX_HONOURED_RETRY_AFTER_MS)
  }
  const ceiling = Math.min(BASE_DELAY_MS * 2 ** (attempt - 1), MAX_DELAY_MS)
  return Math.round(ceiling * (0.5 + random() * 0.5))
}

/** Reads a Retry-After value, in either of the two forms it may take. */
export function retryAfterMsFrom(raw: string | null | undefined, now: number): number | undefined {
  if (raw === null || raw === undefined || raw.trim() === '') return undefined

  const seconds = Number(raw)
  if (Number.isFinite(seconds)) return Math.max(0, seconds * 1000)

  const at = Date.parse(raw)
  if (Number.isFinite(at)) return Math.max(0, at - now)
  return undefined
}

/** Reads the Retry-After header off a response, in either of its two forms. */
export function retryAfterMs(headers: Headers, now: number): number | undefined {
  return retryAfterMsFrom(headers.get('retry-after'), now)
}

/**
 * The Retry-After a refusal carried, remembered beside the failure it belongs to.
 *
 * It is held here rather than on the error itself because every field on an
 * error is something a consumer can come to depend on, and how long the SDK
 * waited before trying again is the SDK's business. The map is weak, so
 * remembering costs nothing once the caller has let the failure go.
 */
const retryAfterHeaders = new WeakMap<QShieldError, string>()

/** Notes what a refusal said about when to come back. */
export function rememberRetryAfter(error: QShieldError, raw: string | null): void {
  if (raw !== null && raw.trim() !== '') retryAfterHeaders.set(error, raw)
}

/** What a refusal said about when to come back, if it said anything. */
export function retryAfterHeaderOf(error: QShieldError): string | undefined {
  return retryAfterHeaders.get(error)
}

/**
 * Waits, and gives up waiting if the caller cancels.
 *
 * A cancellation here raises the SDK's own cancellation failure rather than the
 * runtime's abort reason. Catching QShieldError has to catch everything the SDK
 * can throw, and a wait between two attempts is no exception to that.
 */
export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted === true) {
      reject(fromEntry(CancelledError, RequestCancelled))
      return
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort)
      resolve()
    }, ms)
    const onAbort = (): void => {
      clearTimeout(timer)
      reject(fromEntry(CancelledError, RequestCancelled))
    }
    signal?.addEventListener('abort', onAbort, { once: true })
  })
}
