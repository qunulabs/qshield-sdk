/**
 * The algorithms this qshield release can build a key from.
 *
 * THIS LIST IS A SUGGESTION, NOT A GATE. An editor offers these names while a
 * caller is typing, and any other string still compiles. That is deliberate:
 * qshield's algorithm catalogue grows with releases, and a closed union would
 * make an older SDK refuse an algorithm the deployment in front of it supports.
 * The server is the authority on what it accepts, and it now says so with a
 * named failure rather than an internal error.
 *
 * The list holds only algorithms a key can be CREATED from, which is a subset of
 * the wider catalogue: hashes, extendable output functions and legacy cipher
 * modes appear in qshield's catalogue but cannot serve any key purpose, so
 * offering them here would only invite a refusal.
 *
 * A guard in the backend proves this list against the live catalogue in both
 * directions, so it cannot quietly go stale or name something that does not
 * exist.
 */

/**
 * Every algorithm identifier a key can be created from, grouped by the purposes
 * it can serve. An algorithm listed twice can serve either purpose.
 */
export const KNOWN_KEY_ALGORITHMS = [
  // signature
  'rsa_2048',
  'rsa_3072',
  'rsa_4096',
  'ecdsa_p256',
  'ecdsa_p384',
  'ecdsa_p521',
  'ed25519',
  'ed448',
  'ml_dsa_44',
  'ml_dsa_65',
  'ml_dsa_87',
  'slh_dsa_sha2_128s',
  'slh_dsa_sha2_128f',
  'slh_dsa_sha2_192s',
  'slh_dsa_sha2_192f',
  'slh_dsa_sha2_256s',
  'slh_dsa_sha2_256f',
  'slh_dsa_shake_128s',
  'slh_dsa_shake_128f',
  'slh_dsa_shake_192s',
  'slh_dsa_shake_192f',
  'slh_dsa_shake_256s',
  'slh_dsa_shake_256f',
  // encryption (rsa_2048, rsa_3072 and rsa_4096 also serve this purpose)
  'aes_128_gcm',
  'aes_256_gcm',
  'chacha20_poly1305',
  // wrapping
  'aes_128',
  'aes_192',
  'aes_256',
  // message authentication
  'hmac_sha256',
  'hmac_sha384',
  'hmac_sha512',
  // key encapsulation
  'ml_kem_512',
  'ml_kem_768',
  'ml_kem_1024',
] as const

/** One of the algorithm identifiers this SDK release knows about. */
export type KnownKeyAlgorithmId = (typeof KNOWN_KEY_ALGORITHMS)[number]

/**
 * An algorithm identifier.
 *
 * Deliberately open: the known names are offered as suggestions, and any string
 * is accepted so a newer deployment's algorithm is never refused by an older
 * SDK. qshield validates the value and answers a named failure when it cannot
 * use it.
 */
export type KeyAlgorithmId = KnownKeyAlgorithmId | (string & {})
