/**
 * Reading a vault response, strictly.
 *
 * A field this SDK is defined to receive and does not receive is a broken
 * response, and the SDK says so. It does NOT substitute an empty string, a zero
 * or the current time: a key whose alias silently became "" or whose creation
 * date silently became now is far harder to diagnose than a failure at the point
 * the response arrived, and it is the kind of quiet damage that reaches a
 * customer's audit trail.
 *
 * Nothing here copies a value into the failure it raises. A vault response
 * carries key material, and a failure is very likely to be logged.
 */

import { ResponseNotUnderstood } from '../internal/codes.js'
import { fromEntry, ProtocolError } from '../internal/errors.js'

function notUnderstood(field: string): never {
  throw fromEntry(ProtocolError, ResponseNotUnderstood, { details: { field } })
}

/** The response body as a record, or a failure if it is not one. */
export function record(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) notUnderstood(field)
  return value as Record<string, unknown>
}

/** A required array, as the payload rather than as a field. */
export function array(value: unknown, field: string): unknown[] {
  if (!Array.isArray(value)) notUnderstood(field)
  return value
}

/** A required string. */
export function str(raw: Record<string, unknown>, field: string): string {
  const value = raw[field]
  if (typeof value !== 'string') notUnderstood(field)
  return value
}

/** A required number. */
export function num(raw: Record<string, unknown>, field: string): number {
  const value = raw[field]
  if (typeof value !== 'number' || !Number.isFinite(value)) notUnderstood(field)
  return value
}

/**
 * A required boolean.
 *
 * Strict on purpose: treating a missing flag as false would answer "this key has
 * no public half" for a response that simply did not say.
 */
export function bool(raw: Record<string, unknown>, field: string): boolean {
  const value = raw[field]
  if (typeof value !== 'boolean') notUnderstood(field)
  return value
}

/** A required timestamp. */
export function date(raw: Record<string, unknown>, field: string): Date {
  const parsed = new Date(str(raw, field))
  if (Number.isNaN(parsed.getTime())) notUnderstood(field)
  return parsed
}

/**
 * An optional string.
 *
 * Absent and empty are the same thing here, because qshield omits an empty
 * string rather than sending one, and a caller should not have to handle both.
 */
export function optStr(raw: Record<string, unknown>, field: string): string | undefined {
  const value = raw[field]
  if (value === undefined || value === null || value === '') return undefined
  if (typeof value !== 'string') notUnderstood(field)
  return value
}

/** An optional timestamp. */
export function optDate(raw: Record<string, unknown>, field: string): Date | undefined {
  if (optStr(raw, field) === undefined) return undefined
  return date(raw, field)
}

/** A required array of records. */
export function records(raw: Record<string, unknown>, field: string): Record<string, unknown>[] {
  const value = raw[field]
  if (!Array.isArray(value)) notUnderstood(field)
  return value.map((entry) => record(entry, field))
}
