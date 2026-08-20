/**
 * The failures the SDK raises.
 *
 * Every one carries the same four parts qshield puts on the wire - the code,
 * the operator message, the developer description and the details map - plus
 * the request identifier, so a customer can quote it to support.
 *
 * A class is chosen from the CODE, and from the HTTP status only when there is
 * no code to go on. Never from message text: matching on wording is exactly the
 * brittleness the catalogue exists to remove, and the wording is allowed to
 * improve at any time.
 *
 * EGN-000 is the platform's placeholder for a path that has not been given a
 * code of its own. It identifies nothing, so it is treated as no code at all
 * and selection falls through to the status.
 */

import type { CodeEntry } from './codes.js'

/** The placeholder qshield sends where a path has no code of its own. */
export const UNCLASSIFIED_CODE = 'EGN-000'

/** What every SDK failure carries. */
export interface QShieldErrorFields {
  /** The catalogue code, for example "EVT-001". */
  readonly code: string
  /** The operator message: what happened, in the customer's terms. */
  readonly message: string
  /** The developer description: what to change. Always present. */
  readonly description: string
  /** Whatever the failure named, such as a field-to-reason map. Never null. */
  readonly details: Readonly<Record<string, string>>
  /** The qshield request identifier, when a response was received. */
  readonly requestId: string | undefined
  /** The HTTP status, when a response was received. */
  readonly status: number | undefined
}

/**
 * The base of every failure the SDK raises. Catching this catches everything
 * the SDK can throw, whatever went wrong and wherever it went wrong.
 */
export class QShieldError extends Error implements QShieldErrorFields {
  readonly code: string
  readonly description: string
  readonly details: Readonly<Record<string, string>>
  readonly requestId: string | undefined
  readonly status: number | undefined

  constructor(fields: QShieldErrorFields, options?: { cause?: unknown }) {
    super(fields.message, options)
    this.name = new.target.name
    this.code = fields.code
    this.description = fields.description
    this.details = fields.details
    this.requestId = fields.requestId
    this.status = fields.status
  }
}

/** The credential was rejected, or a token could not be obtained. */
export class AuthenticationError extends QShieldError {}

/** The caller is known but is not allowed to do this. */
export class PermissionError extends QShieldError {}

/** The route or the operation is reserved for a person, not a service account. */
export class HumanOnlyError extends QShieldError {}

/** The feature is not licensed here, or a licensed limit has been reached. */
export class NotLicensedError extends QShieldError {}

/** The vault is sealed. Unsealing is a human act, so this is never retried. */
export class VaultSealedError extends QShieldError {}

/**
 * A time-constrained key was used before its window opened.
 *
 * The data is not lost and nothing is wrong with your request: the key simply
 * does not work yet. Read the key for the moment the window opens and call
 * again after it.
 *
 * DISTINCT FROM TimeKeyExpiredError ON PURPOSE, and never merge the two. This
 * one is worth waiting for; that one never is.
 */
export class TimeKeyNotYetValidError extends QShieldError {}

/**
 * A time-constrained key's window has closed, or the key was destroyed.
 *
 * PERMANENT. The key material is shredded when the window closes, so anything
 * it protected is unreadable for good and no retry can ever succeed. Extend a
 * key before its window closes, or create a new one.
 */
export class TimeKeyExpiredError extends QShieldError {}

/**
 * The passphrase for a protected time-constrained key was missing or wrong.
 *
 * Its own class rather than a permission refusal, because it is not one: the
 * caller is allowed to use the key and supplied the wrong secret. The passphrase
 * is shown once when the key is created and cannot be recovered.
 */
export class TimeKeyPassphraseRejectedError extends QShieldError {}

/** The request itself was refused as malformed or not acceptable. */
export class RequestError extends QShieldError {}

/**
 * A validation failure. The offending fields are in `details`, keyed by field
 * name. A validation failure never carries a `reason` key, which is how it is
 * told apart from a policy refusal that also answers 400.
 */
export class ValidationError extends RequestError {}

/** The named thing does not exist, or is not visible to this caller. */
export class NotFoundError extends QShieldError {}

/** The thing exists but is not in a state that allows this. */
export class ConflictError extends QShieldError {}

/** The thing existed and is gone for good. */
export class GoneError extends QShieldError {}

/** Too many requests. The only refusal the SDK repeats. */
export class RateLimitError extends QShieldError {}

/** qshield failed internally, or something it depends on did. */
export class ServerError extends QShieldError {}

/** The client was handed a configuration it cannot use. */
export class ConfigurationError extends QShieldError {}

/** No connection could be made, so the request never reached qshield. */
export class ConnectionError extends QShieldError {}

/** No response arrived in time. */
export class TimeoutError extends QShieldError {}

/** The caller cancelled the request. */
export class CancelledError extends QShieldError {}

/** The response was not the shape this endpoint is defined to return. */
export class ProtocolError extends QShieldError {}

/** Builds a failure the SDK detected itself, from its own code block. */
export function fromEntry(
  Kind: new (fields: QShieldErrorFields, options?: { cause?: unknown }) => QShieldError,
  entry: CodeEntry,
  extra?: { details?: Record<string, string>; cause?: unknown },
): QShieldError {
  return new Kind(
    {
      code: entry.code,
      message: entry.operator,
      description: entry.developer,
      details: Object.freeze({ ...(extra?.details ?? {}) }),
      requestId: undefined,
      status: undefined,
    },
    extra?.cause === undefined ? undefined : { cause: extra.cause },
  )
}

/**
 * The class each catalogue code maps to.
 *
 * Only codes whose class is not obvious from the status appear here. Everything
 * else falls through to the status table below, which keeps this list from
 * having to grow with every code the platform adds.
 */
const byCode: Readonly<Record<string, new (fields: QShieldErrorFields) => QShieldError>> = {
  // Credentials and tokens.
  'EGN-001': AuthenticationError,
  'EGN-002': AuthenticationError,
  'EGN-003': AuthenticationError,
  'EGN-004': AuthenticationError,
  'EGN-005': AuthenticationError,
  'EGN-036': AuthenticationError,

  // A person is required, one way or another.
  'EGN-007': HumanOnlyError,
  'EGN-009': HumanOnlyError,
  'EGN-014': HumanOnlyError,
  'EGN-015': HumanOnlyError,
  'EPK-001': HumanOnlyError,

  // Licensing, which answers 403 like a permission refusal but is not one.
  'EGN-006': NotLicensedError,
  'EGN-017': NotLicensedError,
  'EGN-018': NotLicensedError,
  'EVT-006': NotLicensedError,
  'EPK-004': NotLicensedError,
  'EPK-005': NotLicensedError,

  // Validation, which answers 400 like a plain refusal but carries fields.
  //
  // A coded refusal that names the field the caller got wrong belongs here too,
  // whatever produced it. EVT-012 and EVT-016 are validation in everything but
  // origin - the value arrived in the request, the response says which field it
  // was, and the fix is to send a different one - so a caller reading `details`
  // through a catch on ValidationError must meet them there rather than having to
  // know which layer of qshield rejected the value.
  'EGN-019': ValidationError,
  'EVT-012': ValidationError,
  'EVT-016': ValidationError,

  // The sealed vault, which answers 503 like an outage but is not one and must
  // never be repeated.
  'EVT-001': VaultSealedError,
  'EPK-006': VaultSealedError,

  // The three ways a time-constrained key refuses. Each one is mapped because
  // the status alone would lose the distinction that matters: 422 reads as an
  // ordinary bad request, 410 as any vanished thing, and 403 as a permission
  // refusal, which the passphrase failure is emphatically not.
  'EVT-007': TimeKeyNotYetValidError,
  'EVT-008': TimeKeyExpiredError,
  'EVT-009': TimeKeyPassphraseRejectedError,
}

/** The class each HTTP status maps to when no usable code was sent. */
function byStatus(status: number): new (fields: QShieldErrorFields) => QShieldError {
  if (status === 401) return AuthenticationError
  if (status === 403) return PermissionError
  if (status === 404) return NotFoundError
  if (status === 409) return ConflictError
  if (status === 410) return GoneError
  if (status === 429) return RateLimitError
  if (status >= 500) return ServerError
  if (status >= 400) return RequestError
  return QShieldError
}

/**
 * The class each machine-readable REASON maps to, for the paths qshield has not
 * given a code of its own yet.
 *
 * These three predate the catalogue and are the ONLY discriminator those paths
 * carry. Without them, a deployment where vault is not licensed at all is
 * indistinguishable from a missing permission: both answer 403 with EGN-000, and
 * a caller would have to read English to tell "buy this" from "grant this". The
 * reason is read only when there is no usable code, so a migrated path always
 * wins, and this table shrinks to nothing as the migration reaches them.
 */
const byReason: Readonly<Record<string, new (fields: QShieldErrorFields) => QShieldError>> = {
  feature_unlicensed: NotLicensedError,
  feature_limit_reached: NotLicensedError,
  human_only_endpoint: HumanOnlyError,
}

/**
 * Chooses the class for a response failure: the code first, then the reason, then
 * the status.
 *
 * A code the SDK has never heard of is not an error in itself. The platform
 * adds codes as domains migrate, and an older SDK meeting a newer code must
 * still produce a sensible class rather than refusing to work.
 */
export function classify(
  code: string,
  status: number,
  details: Readonly<Record<string, string>> = {},
): new (fields: QShieldErrorFields) => QShieldError {
  if (code !== '' && code !== UNCLASSIFIED_CODE) {
    const mapped = byCode[code]
    if (mapped !== undefined) return mapped
  }
  const reason = details['reason']
  if (reason !== undefined) {
    const mapped = byReason[reason]
    if (mapped !== undefined) return mapped
  }
  return byStatus(status)
}
