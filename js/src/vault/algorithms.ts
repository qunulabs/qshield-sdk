/**
 * The algorithms this qshield release can build a key from.
 *
 * THESE LISTS ARE SUGGESTIONS, NOT GATES. An editor offers these names while a
 * caller is typing, and any other string still compiles. That is deliberate:
 * qshield's algorithm catalogue grows with releases, and a closed union would
 * make an older SDK refuse an algorithm the deployment in front of it supports.
 * The server is the authority on what it accepts, and it says so with a named
 * failure rather than an internal error.
 *
 * They hold only algorithms a key can be CREATED from, which is a subset of the
 * wider catalogue: hashes, extendable output functions and the scanner-only
 * legacy entries appear in qshield's catalogue and no key is ever made of them,
 * so offering them here would only invite a refusal.
 *
 * THERE ARE TWO LISTS BECAUSE THERE ARE TWO ADMISSION RULES, and one list would
 * be wrong for whichever call it did not describe.
 *
 * A STORED key serves a purpose - it signs, or it encrypts, or it wraps, or it
 * authenticates a message - and qshield keeps it. A DATA key serves no purpose
 * at all: it is raw symmetric material qshield mints, wraps under your workspace
 * key and forgets, for your own encryption code to use. The sets overlap without
 * either containing the other. RSA is a stored key and never a data key. AES-CCM
 * and AES-CBC are data keys and never stored keys, because qshield performs no
 * cipher operation in those modes.
 *
 * ONE WARNING BELONGS WITH THE DATA-KEY LIST, because the code that uses the key
 * is yours. AES-CBC provides confidentiality and NO integrity: ciphertext can be
 * altered undetectably, and decrypting attacker-supplied ciphertext invites a
 * padding oracle. If you take `aes_128_cbc` or `aes_256_cbc` from this list,
 * authenticate the ciphertext as well - an HMAC key from `createKey` over the
 * ciphertext and the IV, or an AEAD mode instead. The GCM and ChaCha20-Poly1305
 * entries authenticate on their own.
 *
 * A guard in the backend proves each list against the live catalogue in both
 * directions, so neither can quietly go stale or name something that does not
 * exist.
 */

/**
 * Every algorithm identifier a STORED vault key can be created from, grouped by
 * the purpose it serves. An algorithm listed twice can serve either purpose.
 *
 * Passed to `client.vault.keys.create` and `client.vault.timeConstrainedKeys.create`.
 * A time-constrained key narrows this further - it must be an asymmetric
 * encryption or key-encapsulation algorithm - and says so at its own call site.
 */
export const KNOWN_STORED_KEY_ALGORITHMS = [
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

/**
 * Every algorithm identifier a DATA key can be created from.
 *
 * Passed to `client.vault.dataKeys.generate`. Read the AES-CBC warning above
 * before choosing one of the last three: qshield mints those keys and performs
 * no encryption with them, so integrity is your code's responsibility.
 */
export const KNOWN_DATA_KEY_ALGORITHMS = [
  // authenticated encryption - integrity comes with the mode
  'aes_128_gcm',
  'aes_256_gcm',
  'chacha20_poly1305',
  // key wrapping, and the deployment default (aes_256)
  'aes_128',
  'aes_192',
  'aes_256',
  // key material only - qshield mints the key, your own code does the encrypting
  'aes_128_ccm',
  'aes_128_cbc',
  'aes_256_cbc',
] as const

/**
 * Every algorithm identifier this release creates a key of, of either kind.
 *
 * Kept as one list for callers that want the whole set. Prefer the specific list
 * for the call you are making: this one names algorithms that each individual
 * create call will refuse.
 */
export const KNOWN_KEY_ALGORITHMS = [
  ...KNOWN_STORED_KEY_ALGORITHMS,
  ...KNOWN_DATA_KEY_ALGORITHMS.filter(
    (id) => !(KNOWN_STORED_KEY_ALGORITHMS as readonly string[]).includes(id),
  ),
] as const

/** One of the stored-key algorithm identifiers this SDK release knows about. */
export type KnownStoredKeyAlgorithmId = (typeof KNOWN_STORED_KEY_ALGORITHMS)[number]

/** One of the data-key algorithm identifiers this SDK release knows about. */
export type KnownDataKeyAlgorithmId = (typeof KNOWN_DATA_KEY_ALGORITHMS)[number]

/** One of the algorithm identifiers this SDK release knows about, of either kind. */
export type KnownKeyAlgorithmId = KnownStoredKeyAlgorithmId | KnownDataKeyAlgorithmId

/**
 * An algorithm identifier.
 *
 * Deliberately open: the known names are offered as suggestions, and any string
 * is accepted so a newer deployment's algorithm is never refused by an older
 * SDK. qshield validates the value and answers a named failure when it cannot
 * use it. The three aliases below differ only in what an editor offers.
 */
export type KeyAlgorithmId = KnownKeyAlgorithmId | (string & {})

/** An algorithm identifier for a stored vault key. */
export type StoredKeyAlgorithmId = KnownStoredKeyAlgorithmId | (string & {})

/** An algorithm identifier for a data key. */
export type DataKeyAlgorithmId = KnownDataKeyAlgorithmId | (string & {})
