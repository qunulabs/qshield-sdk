/**
 * Binary at the boundary.
 *
 * qshield carries every byte string base64 encoded inside JSON. Base64 is a wire
 * detail: it appears in no public type, in either direction, and the conversion
 * happens here so that no namespace repeats it and no two namespaces disagree
 * about it.
 */

import { ResponseNotUnderstood } from './codes.js'
import { fromEntry, ProtocolError } from './errors.js'

/** Standard base64, with the padding the encoder always writes. */
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/

/**
 * Decodes a base64 field into bytes.
 *
 * The decode is STRICT, and deliberately so. Node's decoder skips anything it
 * does not recognise and truncates rather than complaining, which would turn a
 * damaged public key into a shorter public key that looks perfectly valid and
 * verifies nothing. The value is checked and the result is re-encoded and
 * compared, so only an exact round trip is accepted.
 *
 * A value that fails is a broken response, not a caller mistake, so it raises
 * the SDK's own "not understood" failure. The offending text is NOT copied into
 * that failure: a field decoded here is key material, and a failure is very
 * likely to be logged.
 */
export function fromBase64(value: string): Uint8Array {
  if (!BASE64.test(value)) throw fromEntry(ProtocolError, ResponseNotUnderstood)
  const buffer = Buffer.from(value, 'base64')
  if (buffer.toString('base64') !== value) throw fromEntry(ProtocolError, ResponseNotUnderstood)
  return Uint8Array.from(buffer)
}

/**
 * Encodes bytes for a request field.
 *
 * The counterpart to fromBase64, and the only place a caller's bytes become a
 * wire value. Node's encoder is exact in this direction, so there is nothing to
 * guard against here; the function exists so that no namespace repeats the
 * conversion and no two namespaces can disagree about which encoding qshield
 * speaks. It is standard base64 with padding, never the URL-safe alphabet.
 */
export function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64')
}
