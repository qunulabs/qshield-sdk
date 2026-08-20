/**
 * `client.vault.timeConstrainedKeys` - keys that only work for a while.
 *
 * An ordinary key works until somebody deletes it. One of these works between
 * two moments, and when the second one passes qshield DESTROYS the material
 * rather than marking it unusable. That single difference is what the whole
 * namespace is shaped around, and it is not reversible by anyone.
 *
 *   const key = await client.vault.timeConstrainedKeys.create({
 *     alias: 'quarter-close',
 *     algorithmId: 'rsa_3072',
 *     notBefore: new Date('2026-10-01T00:00:00Z'),
 *     notAfter: new Date('2026-10-08T00:00:00Z'),
 *     passphraseProtected: true,
 *   })
 *   if (key.passphraseProtected) store(key.passphrase)   // shown once, right here
 *
 * ENCRYPTING AND DECRYPTING ARE GATED DIFFERENTLY, and that asymmetry is the
 * feature rather than an accident. You can encrypt to the key from the moment it
 * exists, including before the window opens, because encrypting only needs the
 * public half. You can decrypt only INSIDE the window. So data can be sealed
 * today that nobody can open until a chosen date, and that nobody can ever open
 * after another.
 *
 * THREE THINGS CAN REFUSE YOU, AND THEY ARE THREE DIFFERENT FAILURES. Too early
 * is worth waiting for. Too late never is, because the key is gone. A wrong
 * passphrase is neither. Branch on the class, not on the message.
 *
 * Nothing here caches the window status. A key that read `active` a moment ago
 * can be closed by the time you use it, and a client that checked first and
 * trusted the answer would be wrong exactly when it matters. Call the operation
 * and handle its failure.
 */

import { fromBase64, toBase64 } from '../internal/binary.js'
import { ResponseNotUnderstood } from '../internal/codes.js'
import { fromEntry, ProtocolError } from '../internal/errors.js'
import type { Requester } from '../internal/requester.js'
import type { KeyAlgorithmId } from './algorithms.js'
import { array, bool, date, optDate, optStr, record, str } from './decode.js'
import type {
  CreatedTimeConstrainedKey,
  TimeConstrainedKey,
  TimeKeyEncapsulation,
  TimeKeyPublicKey,
} from './types.js'

const TC_KEYS = '/api/v1/vault/tc-keys'

/**
 * One options type per method, as everywhere else in this package, and separate
 * names even where two are identical today so they can diverge later.
 *
 * `passphrase` appears on the four operations that touch the private half of a
 * protected key. It is optional on every one of them because a key that is not
 * protected needs none; sending it for such a key is refused rather than
 * ignored.
 */
export interface ListTimeConstrainedKeysOptions {
  readonly signal?: AbortSignal
}

export interface CreateTimeConstrainedKeyOptions {
  /**
   * The name to address the key by. Letters, digits, hyphens and underscores, up
   * to 64 characters, and unique within your workspace.
   */
  readonly alias: string
  /**
   * The algorithm to build the key from. It must be an asymmetric one: qshield
   * derives the key's purpose from it, and a symmetric algorithm is refused
   * because there would be no public half to hand out.
   */
  readonly algorithmId: KeyAlgorithmId
  /** When the key starts working. */
  readonly notBefore: Date
  /**
   * When the key stops working, for good.
   *
   * It must be after `notBefore` and in the future. At this moment the key
   * material is destroyed, not disabled, so choose it with the lifetime of the
   * data in mind rather than the lifetime of the key.
   */
  readonly notAfter: Date
  /** A note to keep with the key. */
  readonly description?: string
  /**
   * Whether to protect the key with a passphrase.
   *
   * Turning this on binds the private half to a secret qshield generates and
   * shows you ONCE, on the result of this call. Every later use of the private
   * half needs it, and NOBODY can bypass it, including an administrator. That is
   * the point of the option; do not turn it on without somewhere to put the
   * passphrase.
   */
  readonly passphraseProtected?: boolean
  readonly signal?: AbortSignal
}

export interface GetTimeConstrainedKeyOptions {
  readonly alias: string
  readonly signal?: AbortSignal
}

export interface TimeKeyPublicKeyOptions {
  readonly alias: string
  readonly signal?: AbortSignal
}

export interface TimeKeyEncryptOptions {
  readonly alias: string
  readonly plaintext: Uint8Array
  /**
   * An optional label bound to the ciphertext. The SAME label must be given to
   * decrypt or the decrypt fails, and the SDK does not remember it for you: it
   * is yours to keep beside the ciphertext.
   */
  readonly label?: Uint8Array
  readonly signal?: AbortSignal
}

export interface TimeKeyDecryptOptions {
  readonly alias: string
  readonly ciphertext: Uint8Array
  /** The exact label used when encrypting, if any. */
  readonly label?: Uint8Array
  /** The passphrase from the create result. Required if the key is protected. */
  readonly passphrase?: string
  readonly signal?: AbortSignal
}

export interface TimeKeyEncapsulateOptions {
  readonly alias: string
  readonly signal?: AbortSignal
}

export interface TimeKeyDecapsulateOptions {
  readonly alias: string
  /** The ciphertext produced by encapsulating to this key. */
  readonly ciphertext: Uint8Array
  /** The passphrase from the create result. Required if the key is protected. */
  readonly passphrase?: string
  readonly signal?: AbortSignal
}

export interface ExtendTimeConstrainedKeyOptions {
  readonly alias: string
  /**
   * The new moment for the window to close.
   *
   * FORWARD ONLY. It must be later than the current one; a window cannot be
   * shortened, and an expired key cannot be brought back. Extend before the
   * window closes, not after.
   */
  readonly notAfter: Date
  /** The passphrase from the create result. Required if the key is protected. */
  readonly passphrase?: string
  readonly signal?: AbortSignal
}

export interface DestroyTimeConstrainedKeyOptions {
  readonly alias: string
  /** The passphrase from the create result. Required if the key is protected. */
  readonly passphrase?: string
  readonly signal?: AbortSignal
}

/** Keys with a validity window. Reached as `client.vault.timeConstrainedKeys`. */
export class TimeConstrainedKeysNamespace {
  readonly #requester: Requester

  constructor(requester: Requester) {
    this.#requester = requester
  }

  /**
   * Every time-constrained key in your workspace.
   *
   * Keys that have closed are included until they are swept away, reported with
   * an `expired` or `destroyed` window status. They cannot be used.
   */
  async list(options: ListTimeConstrainedKeysOptions = {}): Promise<TimeConstrainedKey[]> {
    const result = await this.#requester.json<unknown>({
      method: 'GET',
      path: TC_KEYS,
      signal: options.signal,
    })
    return array(result.data, 'data').map(toTimeKey)
  }

  /**
   * Creates a key with a validity window.
   *
   * THIS IS THE ONLY CALL THAT EVER RETURNS THE PASSPHRASE. If you asked for a
   * protected key, store it from the result before doing anything else: it is
   * not recorded anywhere, cannot be reset, and without it the key can be
   * neither used, extended nor destroyed.
   */
  async create(options: CreateTimeConstrainedKeyOptions): Promise<CreatedTimeConstrainedKey> {
    const result = await this.#requester.json<unknown>({
      method: 'POST',
      path: TC_KEYS,
      body: {
        alias: options.alias,
        algorithm_id: options.algorithmId,
        not_before: options.notBefore.toISOString(),
        not_after: options.notAfter.toISOString(),
        ...(options.description === undefined ? {} : { description: options.description }),
        ...(options.passphraseProtected === undefined
          ? {}
          : { passphrase_protected: options.passphraseProtected }),
      },
      signal: options.signal,
    })

    const raw = record(result.data, 'data')
    const key = toTimeKey(raw)
    const publicKey = fromBase64(str(raw, 'public_key'))

    if (!key.passphraseProtected) {
      return { ...key, passphraseProtected: false, publicKey }
    }
    // A protected key whose response carries no passphrase is a broken response,
    // not a key with an empty one. Saying so here is the only chance anybody
    // gets: the passphrase is never sent again, so a caller who stored nothing
    // would find out at the first decrypt, with the key already unusable.
    const passphrase = optStr(raw, 'passphrase')
    if (passphrase === undefined) {
      throw fromEntry(ProtocolError, ResponseNotUnderstood, { details: { field: 'passphrase' } })
    }
    return { ...key, passphraseProtected: true, publicKey, passphrase }
  }

  /** Reads one key. Metadata only; the passphrase is never included. */
  async get(options: GetTimeConstrainedKeyOptions): Promise<TimeConstrainedKey> {
    const result = await this.#requester.json<unknown>({
      method: 'GET',
      path: `${TC_KEYS}/${encodeURIComponent(options.alias)}`,
      signal: options.signal,
    })
    return toTimeKey(record(result.data, 'data'))
  }

  /**
   * The public half of a key.
   *
   * Safe to hand out. Whoever holds it can encrypt to the key on their own,
   * without a qshield credential, and without being able to read anything back.
   */
  async publicKey(options: TimeKeyPublicKeyOptions): Promise<TimeKeyPublicKey> {
    const result = await this.#requester.json<unknown>({
      method: 'GET',
      path: `${TC_KEYS}/${encodeURIComponent(options.alias)}/public-key`,
      signal: options.signal,
    })
    const body = record(result.data, 'data')
    return {
      algorithmId: str(body, 'algorithm_id'),
      publicKey: fromBase64(str(body, 'public_key')),
    }
  }

  /**
   * Encrypts to the key.
   *
   * ALLOWED BEFORE THE WINDOW OPENS, and refused only once it has closed. This
   * uses the public half, so sealing data for a date in the future is the normal
   * way to use these keys rather than a trick.
   *
   * No passphrase is involved, whatever the key. A passphrase protects the
   * private half, and this call does not touch it.
   */
  async encrypt(options: TimeKeyEncryptOptions): Promise<Uint8Array> {
    const result = await this.#requester.json<unknown>({
      method: 'POST',
      path: `${TC_KEYS}/${encodeURIComponent(options.alias)}/encrypt`,
      body: {
        plaintext: toBase64(options.plaintext),
        ...labelField(options.label),
      },
      signal: options.signal,
    })
    return fromBase64(str(record(result.data, 'data'), 'ciphertext'))
  }

  /**
   * Decrypts with the key.
   *
   * Only inside the window. Before it opens you get a not-yet-valid failure and
   * waiting will fix it; after it closes you get an expired failure and nothing
   * will, because the material is gone.
   */
  async decrypt(options: TimeKeyDecryptOptions): Promise<Uint8Array> {
    const result = await this.#requester.json<unknown>({
      method: 'POST',
      path: `${TC_KEYS}/${encodeURIComponent(options.alias)}/decrypt`,
      body: {
        ciphertext: toBase64(options.ciphertext),
        ...labelField(options.label),
        ...passphraseField(options.passphrase),
      },
      signal: options.signal,
    })
    return fromBase64(str(record(result.data, 'data'), 'plaintext'))
  }

  /**
   * Derives a shared secret and the ciphertext that recovers it.
   *
   * The encapsulation counterpart of `encrypt`, for a key whose purpose is
   * encapsulation, and gated the same way: allowed until the window closes,
   * because it uses the public half only.
   *
   * The options object carries nothing but the alias today. It exists so that a
   * parameter can be added later without breaking anyone.
   */
  async encapsulate(options: TimeKeyEncapsulateOptions): Promise<TimeKeyEncapsulation> {
    const result = await this.#requester.json<unknown>({
      method: 'POST',
      path: `${TC_KEYS}/${encodeURIComponent(options.alias)}/encapsulate`,
      body: {},
      signal: options.signal,
    })
    const body = record(result.data, 'data')
    return {
      ciphertext: fromBase64(str(body, 'ciphertext')),
      sharedSecret: fromBase64(str(body, 'shared_secret')),
    }
  }

  /**
   * Recovers the shared secret from an encapsulation ciphertext.
   *
   * Window gated and passphrase gated, exactly like `decrypt`.
   */
  async decapsulate(options: TimeKeyDecapsulateOptions): Promise<Uint8Array> {
    const result = await this.#requester.json<unknown>({
      method: 'POST',
      path: `${TC_KEYS}/${encodeURIComponent(options.alias)}/decapsulate`,
      body: {
        ciphertext: toBase64(options.ciphertext),
        ...passphraseField(options.passphrase),
      },
      signal: options.signal,
    })
    return fromBase64(str(record(result.data, 'data'), 'shared_secret'))
  }

  /**
   * Moves the end of the window later.
   *
   * Forward only, and only while the key is still alive. Once a window has
   * closed the material has been destroyed, so there is nothing left to extend
   * and this fails with the expired failure like every other call.
   *
   * Extending re-seals the key, so a protected key needs its passphrase here.
   */
  async extend(options: ExtendTimeConstrainedKeyOptions): Promise<TimeConstrainedKey> {
    const result = await this.#requester.json<unknown>({
      method: 'POST',
      path: `${TC_KEYS}/${encodeURIComponent(options.alias)}/extend`,
      body: {
        new_not_after: options.notAfter.toISOString(),
        ...passphraseField(options.passphrase),
      },
      signal: options.signal,
    })
    return toTimeKey(record(result.data, 'data'))
  }

  /**
   * Destroys the key now, without waiting for its window to close.
   *
   * IMMEDIATE AND UNRECOVERABLE. This is not a soft delete and there is no
   * tombstone to read back: the material is shredded, everything the key
   * protected becomes unreadable, and no later call can undo it. It is what you
   * reach for when a key must stop working sooner than planned.
   *
   * A protected key needs its passphrase, so that holding the permission to
   * destroy is not by itself enough to take out a key somebody else sealed.
   *
   * Destroying a key that is already destroyed succeeds and changes nothing.
   */
  async destroy(options: DestroyTimeConstrainedKeyOptions): Promise<void> {
    await this.#requester.json<unknown>({
      method: 'POST',
      path: `${TC_KEYS}/${encodeURIComponent(options.alias)}/destroy`,
      body: { ...passphraseField(options.passphrase) },
      signal: options.signal,
    })
  }
}

/** The optional label field, spread into a request body. */
function labelField(label: Uint8Array | undefined): Record<string, string> {
  return label === undefined ? {} : { label: toBase64(label) }
}

/**
 * The optional passphrase field, spread into a request body.
 *
 * Written once because four operations carry it. It never travels in a path or a
 * query string, only in the body, so it cannot end up in an access log.
 */
function passphraseField(passphrase: string | undefined): Record<string, string> {
  return passphrase === undefined ? {} : { passphrase }
}

/** Reads one key. Never reads the passphrase; `create` does that, alone. */
function toTimeKey(value: unknown): TimeConstrainedKey {
  const raw = record(value, 'data')

  const description = optStr(raw, 'description')
  const destroyedAt = optDate(raw, 'destroyed_at')

  return {
    id: str(raw, 'id'),
    alias: str(raw, 'alias'),
    ...(description === undefined ? {} : { description }),
    algorithmId: str(raw, 'algorithm_id'),
    purpose: str(raw, 'purpose'),
    passphraseProtected: bool(raw, 'passphrase_protected'),
    notBefore: date(raw, 'not_before'),
    notAfter: date(raw, 'not_after'),
    windowStatus: str(raw, 'window_status'),
    createdAt: date(raw, 'created_at'),
    updatedAt: date(raw, 'updated_at'),
    ...(destroyedAt === undefined ? {} : { destroyedAt }),
  }
}
