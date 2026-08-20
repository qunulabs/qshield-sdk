/**
 * `client.vault.keys` - the keys in your workspace.
 *
 * Every method takes exactly one options object, including the ones that need
 * only an alias today. That is what lets a parameter be added later without
 * breaking anyone, and it is a rule with no exceptions rather than a judgement
 * made per method.
 *
 * Nothing here retries a refusal. In particular a sealed vault answers every one
 * of these calls and is never repeated: unsealing is a human act that can take
 * hours, so a typed failure is worth more than a client that hangs.
 *
 * ONE RULE DECIDES EVERY RETURN SHAPE. Where qshield returns exactly one thing,
 * the method returns that thing: `decrypt` gives you the plaintext and
 * `decapsulate` gives you the shared secret. Where it returns more than one, the
 * method returns a named object, so a field can be added to it later without
 * breaking anyone. Applying that rule per method is how two methods end up
 * disagreeing; it is written down here so it is applied once.
 */

import { fromBase64, toBase64 } from '../internal/binary.js'
import type { Requester } from '../internal/requester.js'
import type { KeyAlgorithmId } from './algorithms.js'
import { array, bool, date, num, optDate, optStr, record, records, str } from './decode.js'
import type {
  EncapsulateResult,
  EncryptResult,
  HmacResult,
  Key,
  KeyCloudOrigin,
  KeyPublicKey,
  KeyPurpose,
  KeyVersions,
  SignResult,
} from './types.js'

const KEYS = '/api/v1/vault/keys'

/**
 * Each method has its own options type, even where two are identical today.
 * They are separate names because they will diverge: a parameter added to one
 * operation must not silently appear on another, and a shared type would make
 * that impossible to avoid once published.
 *
 * `signal` cancels the call. The SDK stops waiting; whether qshield finished the
 * work is undefined, exactly as for any cancelled request.
 */
export interface ListKeysOptions {
  readonly signal?: AbortSignal
}

export interface CreateKeyOptions {
  /**
   * The name to address the key by. Letters, digits, hyphens and underscores,
   * up to 64 characters, and unique within your workspace.
   */
  readonly alias: string
  /**
   * The algorithm to build the key from. Your editor offers the algorithms this
   * release ships; any identifier this deployment knows is accepted.
   */
  readonly algorithmId: KeyAlgorithmId
  /** What the key is for. The algorithm must be able to serve it. */
  readonly purpose: KeyPurpose
  /**
   * How often to rotate the key, as a duration such as `720h`. Omit it and the
   * key is never rotated automatically. qshield validates the value and
   * normalises it, so what comes back is equivalent but not identical.
   */
  readonly rotationInterval?: string
  readonly signal?: AbortSignal
}

export interface GetKeyOptions {
  readonly alias: string
  readonly signal?: AbortSignal
}

export interface KeyVersionsOptions {
  readonly alias: string
  readonly signal?: AbortSignal
}

export interface KeyPublicKeyOptions {
  readonly alias: string
  /**
   * Which version to read. Omit it for the current one. Versions start at 1 and
   * rise by one on every rotation.
   */
  readonly version?: number
  readonly signal?: AbortSignal
}

export interface RotateKeyOptions {
  readonly alias: string
  readonly signal?: AbortSignal
}

export interface DeleteKeyOptions {
  readonly alias: string
  readonly signal?: AbortSignal
}

/**
 * The crypto operations.
 *
 * Every one of them takes an optional `version`. Omit it and qshield uses the
 * key's current version, which is what you want unless you are working with data
 * protected under an older one. Rotation leaves earlier versions usable, so this
 * is a selector and not a migration.
 *
 * Every binary field is bytes. The SDK converts, and base64 appears nowhere.
 */
export interface SignOptions {
  readonly alias: string
  /** The bytes to sign. qshield hashes them; do not pre-hash. */
  readonly message: Uint8Array
  readonly version?: number
  readonly signal?: AbortSignal
}

export interface VerifyOptions {
  readonly alias: string
  /** The bytes the signature was made over. */
  readonly message: Uint8Array
  readonly signature: Uint8Array
  /**
   * Which version made the signature. Omit it for the current one, which is
   * wrong as soon as the key has rotated: keep the version from the sign result
   * and pass it here.
   */
  readonly version?: number
  readonly signal?: AbortSignal
}

export interface EncryptOptions {
  readonly alias: string
  readonly plaintext: Uint8Array
  /**
   * Additional authenticated data. It is not encrypted, it is bound to the
   * ciphertext, and the SAME value must be given to decrypt or the decrypt
   * fails. The SDK does not remember it for you: it is yours to store alongside
   * the ciphertext, and that is deliberate, because guessing it back would make
   * the binding meaningless.
   */
  readonly additionalData?: Uint8Array
  readonly version?: number
  readonly signal?: AbortSignal
}

export interface DecryptOptions {
  readonly alias: string
  readonly ciphertext: Uint8Array
  /** The exact additional authenticated data used when encrypting, if any. */
  readonly additionalData?: Uint8Array
  readonly version?: number
  readonly signal?: AbortSignal
}

export interface HmacOptions {
  readonly alias: string
  readonly message: Uint8Array
  readonly version?: number
  readonly signal?: AbortSignal
}

export interface EncapsulateOptions {
  readonly alias: string
  readonly version?: number
  readonly signal?: AbortSignal
}

export interface DecapsulateOptions {
  readonly alias: string
  /** The ciphertext produced by encapsulating to this key. */
  readonly ciphertext: Uint8Array
  readonly version?: number
  readonly signal?: AbortSignal
}

/** The keys in your workspace. Reached as `client.vault.keys`. */
export class KeysNamespace {
  readonly #requester: Requester

  constructor(requester: Requester) {
    this.#requester = requester
  }

  /**
   * Every key in your workspace, oldest first.
   *
   * Deleted keys are included, reported with a `deleted` state. They are kept so
   * that an operator can still see a key existed; they are not usable. Filter on
   * `state` if you only want keys you can work with.
   */
  async list(options: ListKeysOptions = {}): Promise<Key[]> {
    const result = await this.#requester.json<unknown>({
      method: 'GET',
      path: KEYS,
      signal: options.signal,
    })
    return array(result.data, 'data').map(toKey)
  }

  /** Creates a key. */
  async create(options: CreateKeyOptions): Promise<Key> {
    const result = await this.#requester.json<unknown>({
      method: 'POST',
      path: KEYS,
      body: {
        alias: options.alias,
        algorithm_id: options.algorithmId,
        purpose: options.purpose,
        ...(options.rotationInterval === undefined
          ? {}
          : { rotation_interval: options.rotationInterval }),
      },
      signal: options.signal,
    })
    return toKey(result.data)
  }

  /** Reads one key. */
  async get(options: GetKeyOptions): Promise<Key> {
    const result = await this.#requester.json<unknown>({
      method: 'GET',
      path: `${KEYS}/${encodeURIComponent(options.alias)}`,
      signal: options.signal,
    })
    return toKey(result.data)
  }

  /**
   * The version history of a key.
   *
   * Metadata only. No key material travels on this call, whatever the key is.
   */
  async versions(options: KeyVersionsOptions): Promise<KeyVersions> {
    const result = await this.#requester.json<unknown>({
      method: 'GET',
      path: `${KEYS}/${encodeURIComponent(options.alias)}/versions`,
      signal: options.signal,
    })
    const body = record(result.data, 'data')
    return {
      alias: str(body, 'alias'),
      currentVersion: num(body, 'current_version'),
      versions: records(body, 'versions').map((raw) => ({
        version: num(raw, 'version'),
        kekVersion: num(raw, 'kek_version'),
        state: str(raw, 'state'),
        hasPublicKey: bool(raw, 'has_public_key'),
        createdAt: date(raw, 'created_at'),
      })),
    }
  }

  /**
   * The public half of a key.
   *
   * Only a key pair has one. Asking a symmetric or message-authentication key
   * for a public key is its own failure, not a missing key, so a caller can tell
   * a wrong key kind from a wrong alias.
   */
  async publicKey(options: KeyPublicKeyOptions): Promise<KeyPublicKey> {
    const result = await this.#requester.json<unknown>({
      method: 'GET',
      path: `${KEYS}/${encodeURIComponent(options.alias)}/public-key`,
      query: { version: options.version },
      signal: options.signal,
    })
    const body = record(result.data, 'data')
    return {
      alias: str(body, 'alias'),
      algorithmId: str(body, 'algorithm_id'),
      version: num(body, 'version'),
      publicKey: fromBase64(str(body, 'public_key')),
    }
  }

  /**
   * Rotates a key, creating a new current version.
   *
   * Earlier versions stay usable for decryption and verification, so anything
   * already protected under them keeps working.
   *
   * A key imported from a cloud key service cannot be rotated here; rotate it
   * with the provider and qshield picks the new version up.
   */
  async rotate(options: RotateKeyOptions): Promise<Key> {
    const result = await this.#requester.json<unknown>({
      method: 'POST',
      path: `${KEYS}/${encodeURIComponent(options.alias)}/rotate`,
      signal: options.signal,
    })
    return toKey(result.data)
  }

  /**
   * Deletes a key.
   *
   * Deletion is final. The key stops working immediately, everything protected
   * under it becomes unrecoverable, and there is no undelete. The key stays
   * visible in listings as a record that it existed.
   *
   * Deleting a key that is already deleted succeeds and changes nothing.
   */
  async delete(options: DeleteKeyOptions): Promise<void> {
    await this.#requester.json<undefined>({
      method: 'DELETE',
      path: `${KEYS}/${encodeURIComponent(options.alias)}`,
      signal: options.signal,
    })
  }

  /**
   * Signs a message.
   *
   * Keep the returned version beside the signature. Rotation creates a new
   * current version, so a verifier that does not name the version will one day
   * check against the wrong one.
   */
  async sign(options: SignOptions): Promise<SignResult> {
    const result = await this.#requester.json<unknown>({
      method: 'POST',
      path: `${KEYS}/${encodeURIComponent(options.alias)}/sign`,
      body: {
        message: toBase64(options.message),
        ...versionField(options.version),
      },
      signal: options.signal,
    })
    const body = record(result.data, 'data')
    return {
      signature: fromBase64(str(body, 'signature')),
      version: num(body, 'version'),
    }
  }

  /**
   * Checks a signature, and answers true or false.
   *
   * A SIGNATURE THAT DOES NOT MATCH IS FALSE, NOT AN EXCEPTION. That is the one
   * thing false means here, and it is why this method returns a plain boolean:
   * a mismatch is an ordinary answer to an ordinary question, and turning it
   * into an exception pushes callers into a catch block where every failure
   * looks alike and "probably fine" becomes tempting.
   *
   * Everything else throws. A key that cannot verify at all, a key that was
   * deleted, an alias that does not exist: each has its own typed failure,
   * because reporting any of them as false would tell you your data had been
   * tampered with when in fact the check never ran.
   *
   * So: false means this signature is bad. It never means something went wrong.
   */
  async verify(options: VerifyOptions): Promise<boolean> {
    const result = await this.#requester.json<unknown>({
      method: 'POST',
      path: `${KEYS}/${encodeURIComponent(options.alias)}/verify`,
      body: {
        message: toBase64(options.message),
        signature: toBase64(options.signature),
        ...versionField(options.version),
      },
      signal: options.signal,
    })
    return bool(record(result.data, 'data'), 'valid')
  }

  /** Encrypts data under a key. */
  async encrypt(options: EncryptOptions): Promise<EncryptResult> {
    const result = await this.#requester.json<unknown>({
      method: 'POST',
      path: `${KEYS}/${encodeURIComponent(options.alias)}/encrypt`,
      body: {
        plaintext: toBase64(options.plaintext),
        ...aadField(options.additionalData),
        ...versionField(options.version),
      },
      signal: options.signal,
    })
    const body = record(result.data, 'data')
    return {
      ciphertext: fromBase64(str(body, 'ciphertext')),
      version: num(body, 'version'),
    }
  }

  /**
   * Decrypts data, and returns the plaintext.
   *
   * If the data was encrypted with additional authenticated data, the same value
   * must be given here or the decrypt fails.
   */
  async decrypt(options: DecryptOptions): Promise<Uint8Array> {
    const result = await this.#requester.json<unknown>({
      method: 'POST',
      path: `${KEYS}/${encodeURIComponent(options.alias)}/decrypt`,
      body: {
        ciphertext: toBase64(options.ciphertext),
        ...aadField(options.additionalData),
        ...versionField(options.version),
      },
      signal: options.signal,
    })
    return fromBase64(str(record(result.data, 'data'), 'plaintext'))
  }

  /** Computes a message authentication code over a message. */
  async hmac(options: HmacOptions): Promise<HmacResult> {
    const result = await this.#requester.json<unknown>({
      method: 'POST',
      path: `${KEYS}/${encodeURIComponent(options.alias)}/hmac`,
      body: {
        message: toBase64(options.message),
        ...versionField(options.version),
      },
      signal: options.signal,
    })
    const body = record(result.data, 'data')
    return {
      mac: fromBase64(str(body, 'mac')),
      version: num(body, 'version'),
    }
  }

  /**
   * Establishes a shared secret with the holder of a key.
   *
   * This is key establishment for post-quantum algorithms, and it only works on
   * a key created for that job. You get back a ciphertext to send to the key
   * holder and a shared secret to keep. The holder decapsulates the ciphertext
   * and arrives at the same shared secret without it ever crossing the network.
   *
   * Nothing is sent but the key name: the secret is generated during the call.
   */
  async encapsulate(options: EncapsulateOptions): Promise<EncapsulateResult> {
    const result = await this.#requester.json<unknown>({
      method: 'POST',
      path: `${KEYS}/${encodeURIComponent(options.alias)}/encapsulate`,
      body: { ...versionField(options.version) },
      signal: options.signal,
    })
    const body = record(result.data, 'data')
    return {
      ciphertext: fromBase64(str(body, 'ciphertext')),
      sharedSecret: fromBase64(str(body, 'shared_secret')),
      version: num(body, 'version'),
    }
  }

  /**
   * Recovers the shared secret from an encapsulation ciphertext.
   *
   * The other half of encapsulate. Name the version that produced the
   * ciphertext if the key may have rotated since.
   */
  async decapsulate(options: DecapsulateOptions): Promise<Uint8Array> {
    const result = await this.#requester.json<unknown>({
      method: 'POST',
      path: `${KEYS}/${encodeURIComponent(options.alias)}/decapsulate`,
      body: {
        ciphertext: toBase64(options.ciphertext),
        ...versionField(options.version),
      },
      signal: options.signal,
    })
    return fromBase64(str(record(result.data, 'data'), 'shared_secret'))
  }
}

/**
 * The optional version field, spread into a request body.
 *
 * Written once because seven operations carry it and a version that silently
 * became `null` on one of them would select nothing rather than the current
 * version.
 */
function versionField(version: number | undefined): Record<string, number> {
  return version === undefined ? {} : { version }
}

/** The optional additional authenticated data field, spread into a request body. */
function aadField(additionalData: Uint8Array | undefined): Record<string, string> {
  return additionalData === undefined ? {} : { aad: toBase64(additionalData) }
}

/**
 * Reads one key.
 *
 * The three cloud identifiers are gathered into one object, present exactly when
 * the key came from a cloud key service. On the wire they are three independent
 * optional fields, which invites a caller to read one without checking the
 * origin; grouping them makes the dependency between them part of the type.
 */
function toKey(value: unknown): Key {
  const raw = record(value, 'data')
  const origin = str(raw, 'origin')

  let cloud: KeyCloudOrigin | undefined
  if (origin === 'cloud') {
    cloud = {
      connectionId: str(raw, 'connection_id'),
      externalId: str(raw, 'external_id'),
      externalAlias: optStr(raw, 'external_alias') ?? '',
    }
  }

  const rotationInterval = optStr(raw, 'rotation_interval')
  const nextRotationAt = optDate(raw, 'next_rotation_at')

  return {
    id: str(raw, 'id'),
    alias: str(raw, 'alias'),
    algorithmId: str(raw, 'algorithm_id'),
    purpose: str(raw, 'purpose'),
    currentVersion: num(raw, 'current_version'),
    state: str(raw, 'state'),
    origin,
    ...(cloud === undefined ? {} : { cloud }),
    ...(rotationInterval === undefined ? {} : { rotationInterval }),
    ...(nextRotationAt === undefined ? {} : { nextRotationAt }),
    createdAt: date(raw, 'created_at'),
    updatedAt: date(raw, 'updated_at'),
  }
}
