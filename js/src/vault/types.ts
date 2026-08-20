/**
 * The vault key types a customer sees.
 *
 * Every name and every field here is permanent: consumer code compiles against
 * them, so one can be added but never renamed, retyped or removed. What is
 * returned is therefore the smallest set an integration genuinely needs, not
 * everything qshield happens to know.
 *
 * Two typing rules run through this file and are worth understanding before
 * changing anything:
 *
 *  - A value the CALLER sends is a closed union when qshield validates it
 *    against a fixed set. `purpose` is the only one here.
 *  - A value the SERVER returns is an open union: the known values are offered
 *    as suggestions, and any string is still assignable. That is what stops a
 *    consumer writing a switch that a value added in a later release would
 *    break, while still helping them write the common case.
 */

import type { KeyAlgorithmId } from './algorithms.js'

/**
 * What a key is for. Sent by the caller and validated by qshield against exactly
 * this set, so it is closed.
 *
 * A purpose is a capability category rather than one operation: a signature key
 * both signs and verifies, an encryption key both encrypts and decrypts.
 */
export type KeyPurpose = 'signature' | 'encryption' | 'wrapping' | 'mac' | 'encapsulation'

/**
 * The state of a key.
 *
 * A deleted key is a tombstone, not a hidden row: it stays in listings and stays
 * readable, so an operator can still see that it existed and when it went, while
 * every USE of it is refused. Deletion is final and nothing sets a key back to
 * active.
 */
export type KeyState = 'active' | 'deleted' | (string & {})

/**
 * Where a key's material lives.
 *
 * A local key is held by qshield. A cloud key was imported from the customer's
 * own cloud key service: qshield can still use it, because operations are
 * proxied to the provider, but it cannot rotate it. Branch on this when that
 * difference matters to you.
 */
export type KeyOrigin = 'local' | 'cloud' | (string & {})

/** Where a cloud key lives on the provider's side. Present only for a cloud key. */
export interface KeyCloudOrigin {
  /** The cloud key service connection this key came through. */
  readonly connectionId: string
  /** The provider's own identifier for the key. */
  readonly externalId: string
  /** The provider's own alias for the key, when it has one. */
  readonly externalAlias: string
}

/** A key. */
export interface Key {
  readonly id: string
  /** The name the key is addressed by. Unique within your workspace. */
  readonly alias: string
  readonly algorithmId: KeyAlgorithmId
  /** What the key is for. Returned, so any value is possible. */
  readonly purpose: string
  /** The version an operation uses when it is not told otherwise. */
  readonly currentVersion: number
  readonly state: KeyState
  readonly origin: KeyOrigin
  /**
   * The provider-side identity of a cloud key. Present exactly when `origin` is
   * `cloud`, which is why the three identifiers are one object rather than three
   * separate optional fields.
   */
  readonly cloud?: KeyCloudOrigin
  /**
   * How often qshield rotates this key, as a duration.
   *
   * qshield normalises what you send, so a key created with `720h` reports
   * `720h0m0s`. Compare durations by meaning, never by string equality.
   */
  readonly rotationInterval?: string
  /** When the next automatic rotation is due, if the key has a schedule. */
  readonly nextRotationAt?: Date
  readonly createdAt: Date
  readonly updatedAt: Date
}

/**
 * One version of a key.
 *
 * Metadata only. No key material of any kind travels here, and nothing in this
 * type is secret.
 */
export interface KeyVersion {
  readonly version: number
  /** The version of the wrapping key this version is protected under. */
  readonly kekVersion: number
  readonly state: KeyState
  /**
   * Whether this version has a public half to read. False for a symmetric or
   * message-authentication key, which have none.
   */
  readonly hasPublicKey: boolean
  readonly createdAt: Date
}

/** The version history of a key. */
export interface KeyVersions {
  readonly alias: string
  readonly currentVersion: number
  readonly versions: readonly KeyVersion[]
}

/** The public half of one version of a key. */
export interface KeyPublicKey {
  readonly alias: string
  readonly algorithmId: KeyAlgorithmId
  readonly version: number
  /** The public key, in SPKI form. */
  readonly publicKey: Uint8Array
}

/**
 * The results of the crypto operations.
 *
 * Where qshield returns exactly one thing, the method returns that thing and
 * there is no type here for it: `decrypt` returns the plaintext, `decapsulate`
 * returns the shared secret, `verify` returns a boolean. Where it returns more
 * than one, the result is an object, and it is named so a field can be added to
 * it later without breaking anyone.
 *
 * Every binary field is `Uint8Array`, in both directions. Base64 is a wire
 * detail and appears in no type this package publishes.
 */

/** The result of signing a message. */
export interface SignResult {
  readonly signature: Uint8Array
  /**
   * The key version that produced the signature.
   *
   * Worth keeping beside the signature. Rotation creates a new current version
   * and leaves the old ones usable, so a verifier that names this version keeps
   * working no matter how often the key rotates afterwards.
   */
  readonly version: number
}

/** The result of encrypting. */
export interface EncryptResult {
  readonly ciphertext: Uint8Array
  /**
   * The key version that produced the ciphertext. Keep it if you want to name
   * the version on the matching decrypt; qshield finds the right one either way.
   */
  readonly version: number
}

/** The result of computing a message authentication code. */
export interface HmacResult {
  readonly mac: Uint8Array
  readonly version: number
}

/**
 * The result of encapsulating to a key.
 *
 * The two halves go to different places. Send the ciphertext to whoever holds
 * the key; keep the shared secret, which is the key material you encrypt with.
 * The holder recovers the same shared secret by decapsulating the ciphertext.
 */
export interface EncapsulateResult {
  readonly ciphertext: Uint8Array
  readonly sharedSecret: Uint8Array
  readonly version: number
}

/**
 * A freshly generated data key, for envelope encryption.
 *
 * The two halves have different lifetimes and that is the whole point.
 * `key` is the one you encrypt your data with, and you throw it away as soon as
 * you have. `wrapped` is opaque, safe to store beside the ciphertext it protects,
 * and useless to anyone without access to your qshield workspace. Hand it back
 * to `unwrap` when you need the key again.
 *
 * Never store `key`. Storing it beside the data it protects removes every
 * benefit of generating it here.
 */
export interface DataKey {
  /** The data key itself. Use it, then discard it. */
  readonly key: Uint8Array
  /** The same key, protected by your workspace. Store this one. */
  readonly wrapped: Uint8Array
}

/**
 * Time-constrained keys.
 *
 * A key with a validity window: it cannot be used before the window opens, and
 * when the window closes its material is destroyed rather than merely marked
 * unusable. Everything below follows from that.
 */

/**
 * Where a time-constrained key is in its life.
 *
 * `pending` before the window opens, `active` inside it, `expired` after it
 * closes, `destroyed` once the material has actually been shredded.
 *
 * Returned by the server, so any string is possible and this is an open union.
 * TREAT IT AS A READING, NOT A GUARANTEE. Expiry is swept in the background, so
 * a key can report `expired` for a short while before it reports `destroyed`,
 * and a key that reads `active` can close before your next call. Handle the
 * failure on the operation; do not check this first and assume it holds.
 */
export type TimeKeyWindowStatus = 'pending' | 'active' | 'expired' | 'destroyed' | (string & {})

/**
 * A time-constrained key.
 *
 * Metadata only. No key material of any kind travels here, and the passphrase of
 * a protected key appears nowhere on this type: it is shown once, when the key
 * is created, and cannot be recovered afterwards.
 */
export interface TimeConstrainedKey {
  readonly id: string
  /** The name the key is addressed by. Unique within your workspace. */
  readonly alias: string
  /** Whatever note was written when the key was created. */
  readonly description?: string
  readonly algorithmId: KeyAlgorithmId
  /**
   * What the key can do. qshield derives it from the algorithm rather than
   * taking it from you: `encryption` for a key you encrypt to, `encapsulation`
   * for a key you derive a shared secret with. Returned, so any value is
   * possible.
   */
  readonly purpose: string
  /**
   * Whether a passphrase is needed to use the private half. When this is true,
   * decrypting, decapsulating, extending and destroying all need the passphrase
   * issued at creation, and there is no way to recover or reset it.
   */
  readonly passphraseProtected: boolean
  /** When the window opens. The key cannot be used to decrypt before this. */
  readonly notBefore: Date
  /** When the window closes. The key is destroyed at this point, permanently. */
  readonly notAfter: Date
  readonly windowStatus: TimeKeyWindowStatus
  readonly createdAt: Date
  readonly updatedAt: Date
  /** When the material was actually shredded, once that has happened. */
  readonly destroyedAt?: Date
}

/** What a freshly created key carries in addition to its metadata. */
interface NewTimeConstrainedKey extends TimeConstrainedKey {
  /**
   * The public half, in SPKI form.
   *
   * Hand it out. Anyone holding it can encrypt to the key without reaching
   * qshield at all, which is the point of the window: they can seal data now
   * that nobody can open until the window opens, and that nobody can ever open
   * once it closes.
   */
  readonly publicKey: Uint8Array
}

/**
 * A key that has just been created.
 *
 * A DISCRIMINATED UNION, NOT AN OPTIONAL FIELD. Branch on `passphraseProtected`
 * and the passphrase is either there or it is not, decided by the type rather
 * than by a runtime check that a caller can forget.
 *
 * THE PASSPHRASE IS SHOWN EXACTLY ONCE, HERE. It is never returned by any other
 * call, it cannot be reset, and qshield cannot recover it - not even for an
 * administrator, which is deliberate. Store it before you do anything else. Lose
 * it and every use of the key is lost with it, including destroying the key
 * early.
 */
export type CreatedTimeConstrainedKey =
  | (NewTimeConstrainedKey & { readonly passphraseProtected: false })
  | (NewTimeConstrainedKey & { readonly passphraseProtected: true; readonly passphrase: string })

/**
 * The public half of a time-constrained key.
 *
 * These keys have no versions, so unlike an ordinary key there is nothing to
 * name here beyond the algorithm and the bytes.
 */
export interface TimeKeyPublicKey {
  readonly algorithmId: KeyAlgorithmId
  /** The public key, in SPKI form. */
  readonly publicKey: Uint8Array
}

/**
 * The result of encapsulating to a time-constrained key.
 *
 * As for an ordinary key, the two halves go to different places: send the
 * ciphertext to whoever holds the key, keep the shared secret. The difference is
 * that the holder can only recover it while the window is open.
 */
export interface TimeKeyEncapsulation {
  readonly ciphertext: Uint8Array
  readonly sharedSecret: Uint8Array
}
