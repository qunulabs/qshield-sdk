/**
 * Reading what qshield sends back.
 *
 * Every authenticated route answers in the platform envelope: a success flag,
 * the payload, a request identifier, and either paging information or a list of
 * advisories. Failures carry an error object with a code, an operator message, a
 * developer description and whatever the failure named.
 *
 * Three details here have each caused a bug in an existing client, so they are
 * handled deliberately rather than incidentally:
 *
 *  - Unwrapping the payload naively loses the paging information, which a caller
 *    needs to ask for the next page. It is carried out separately.
 *  - The request identifier appears in the body and in a response header. The
 *    header is the one that is always there, including on a failure produced
 *    before the handler ran, so it is preferred.
 *  - Advisories on a successful response are easy to drop on the floor. They are
 *    handed to the warning callback rather than being discarded.
 */

import { ResponseNotUnderstood } from './codes.js'
import { rememberRetryAfter } from './retry.js'
import {
  classify,
  fromEntry,
  ProtocolError,
  type QShieldError,
  type QShieldErrorFields,
} from './errors.js'

/** Paging information on a list response. */
export interface PageInfo {
  readonly page: number
  readonly pageSize: number
  readonly total: number
}

/** A decoded successful response. */
export interface ApiResult<T> {
  readonly data: T
  readonly requestId: string | undefined
  readonly page: PageInfo | undefined
}

/** The response header carrying the request identifier. */
const REQUEST_ID_HEADER = 'x-request-id'

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Reads a JSON body, or raises the SDK's own "not understood" failure.
 *
 * The parse error is deliberately NOT attached as a cause. The runtime puts a
 * fragment of the offending text into its message, and a response body is
 * exactly the thing this SDK never copies anywhere a caller might log it. The
 * code and the developer description already say everything useful about a body
 * that is not the envelope.
 */
export function parseJson(body: Uint8Array): unknown {
  const text = new TextDecoder().decode(body)
  try {
    return JSON.parse(text)
  } catch {
    throw fromEntry(ProtocolError, ResponseNotUnderstood)
  }
}

/** The request identifier, preferring the header because it is always set. */
export function requestIdOf(headers: Headers, parsed: unknown): string | undefined {
  const fromHeader = headers.get(REQUEST_ID_HEADER)
  if (fromHeader !== null && fromHeader !== '') return fromHeader
  if (isRecord(parsed) && typeof parsed['request_id'] === 'string' && parsed['request_id'] !== '') {
    return parsed['request_id']
  }
  return undefined
}

/** Copies the details map, keeping only the string values it is defined to hold. */
function detailsOf(value: unknown): Record<string, string> {
  if (!isRecord(value)) return {}
  const out: Record<string, string> = {}
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry === 'string') out[key] = entry
  }
  return out
}

/**
 * Builds the failure for an error response.
 *
 * A response that is not the envelope at all still has to produce something
 * useful: a reverse proxy answering 502 with an HTML page is a real thing that
 * happens, and "the server said no and here is the status" beats a parse error.
 */
export function errorFrom(
  status: number,
  headers: Headers,
  body: Uint8Array,
): QShieldError {
  let parsed: unknown
  try {
    parsed = parseJson(body)
  } catch {
    parsed = undefined
  }

  const requestId = requestIdOf(headers, parsed)
  const envelopeError = isRecord(parsed) && isRecord(parsed['error']) ? parsed['error'] : undefined

  if (envelopeError === undefined) {
    const entry = ResponseNotUnderstood
    const fields: QShieldErrorFields = {
      code: entry.code,
      message: entry.operator,
      description: entry.developer,
      details: Object.freeze({ status: String(status) }),
      requestId,
      status,
    }
    const failure = new (classify('', status))(fields)
    rememberRetryAfter(failure, headers.get('retry-after'))
    return failure
  }

  const code = typeof envelopeError['code'] === 'string' ? envelopeError['code'] : ''
  const message = typeof envelopeError['message'] === 'string' ? envelopeError['message'] : ''
  const description =
    typeof envelopeError['description'] === 'string' ? envelopeError['description'] : ''

  const details = Object.freeze(detailsOf(envelopeError['details']))
  const fields: QShieldErrorFields = {
    code,
    message,
    description,
    details,
    requestId,
    status,
  }
  const failure = new (classify(code, status, details))(fields)
  rememberRetryAfter(failure, headers.get('retry-after'))
  return failure
}

/**
 * Unwraps a successful envelope, keeping the paging information and passing any
 * advisories to the warning callback.
 *
 * A 204 carries no body at all, and the payload for one is `undefined`. That is
 * the only route shape in the platform where the absence of data is the answer.
 */
export function successFrom<T>(
  status: number,
  headers: Headers,
  body: Uint8Array,
  warn: (warning: string) => void,
): ApiResult<T> {
  if (status === 204 || body.length === 0) {
    return { data: undefined as T, requestId: requestIdOf(headers, undefined), page: undefined }
  }

  const parsed = parseJson(body)
  if (!isRecord(parsed) || parsed['success'] !== true) {
    throw fromEntry(ProtocolError, ResponseNotUnderstood, {
      details: { status: String(status) },
    })
  }

  const warnings = parsed['warnings']
  if (Array.isArray(warnings)) {
    for (const warning of warnings) {
      if (typeof warning === 'string' && warning !== '') warn(warning)
    }
  }

  const meta = parsed['meta']
  let page: PageInfo | undefined
  if (isRecord(meta)) {
    const { page: p, page_size: size, total } = meta
    if (typeof p === 'number' && typeof size === 'number' && typeof total === 'number') {
      page = { page: p, pageSize: size, total }
    }
  }

  return {
    data: parsed['data'] as T,
    requestId: requestIdOf(headers, parsed),
    page,
  }
}
