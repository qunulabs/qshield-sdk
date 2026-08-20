/**
 * `client.vault.dataKeys` - keys for encrypting your own data.
 *
 * This is envelope encryption, and it exists because sending your data to
 * qshield to be encrypted does not scale and often is not allowed. Instead
 * qshield mints a fresh key, hands you two forms of it, and your data never
 * leaves your side.
 *
 *   const dek = await client.vault.dataKeys.generate({})
 *   const blob = encryptLocally(dek.key, myData)   // your own AES, your own code
 *   store(blob, dek.wrapped)                       // keep the wrapped copy
 *   // later
 *   const key = await client.vault.dataKeys.unwrap({ wrapped })
 *
 * TWO RULES MAKE THE WHOLE THING WORK, and breaking either removes the point of
 * it. Discard `key` as soon as you have finished with it, and never write it
 * anywhere. Keep `wrapped` for exactly as long as you keep the data it protects,
 * because it is the only way back to the key.
 *
 * There is deliberately no option to supply your own wrapping key. qshield's
 * route accepts one so that a key can be delivered to a machine that holds the
 * private half, which is a deployment arrangement rather than something an
 * application does; asking every caller to produce a key pair to receive a key
 * would be a hard question with an easy wrong answer.
 */

import { fromBase64, toBase64 } from '../internal/binary.js'
import type { Requester } from '../internal/requester.js'
import type { KeyAlgorithmId } from './algorithms.js'
import { record, str } from './decode.js'
import type { DataKey } from './types.js'

const DATAKEY = '/api/v1/vault/datakey'

export interface GenerateDataKeyOptions {
  /**
   * The algorithm to build the data key from. It must be a symmetric one, such
   * as `aes_256` or `chacha20_poly1305`. Omit it and qshield picks the
   * deployment default, which is what you want unless your own encryption code
   * needs a particular key length.
   *
   * Typed as a string rather than a fixed set, for the same reason as everywhere
   * else in this package: qshield's algorithm catalogue grows with releases, and
   * a closed list here would make an older SDK refuse a newer algorithm.
   */
  readonly algorithmId?: KeyAlgorithmId
  readonly signal?: AbortSignal
}

export interface UnwrapDataKeyOptions {
  /** The wrapped copy handed back by `generate`, byte for byte. */
  readonly wrapped: Uint8Array
  readonly signal?: AbortSignal
}

/** Data keys for envelope encryption. Reached as `client.vault.dataKeys`. */
export class DataKeysNamespace {
  readonly #requester: Requester

  constructor(requester: Requester) {
    this.#requester = requester
  }

  /**
   * Mints a fresh data key.
   *
   * You get the key to encrypt with and a wrapped copy to store. qshield keeps
   * neither; there is nothing to delete afterwards and nothing to list.
   *
   * Your credential needs permission to receive a data key in the clear. Without
   * it the call is refused with a typed failure naming the permission to grant,
   * rather than quietly answering with the key missing - which is what this route
   * used to do, and the reason it can never be modelled as an optional field
   * here.
   */
  async generate(options: GenerateDataKeyOptions = {}): Promise<DataKey> {
    const result = await this.#requester.json<unknown>({
      method: 'POST',
      path: DATAKEY,
      body: {
        return_plaintext: true,
        ...(options.algorithmId === undefined ? {} : { algorithm_id: options.algorithmId }),
      },
      signal: options.signal,
    })
    const body = record(result.data, 'data')
    // Both fields are read strictly. A success that arrives without the key is a
    // broken response, not a DataKey with an empty half, and saying so at the
    // point it arrives is far easier to diagnose than a later decrypt that
    // produces nothing.
    return {
      key: fromBase64(str(body, 'plaintext')),
      wrapped: fromBase64(str(body, 'wrapped')),
    }
  }

  /**
   * Recovers a data key from its wrapped copy.
   *
   * Only the workspace that minted the key can open it, and the bytes must be
   * exactly what `generate` returned. Anything else is a typed refusal rather
   * than a key that decrypts to nothing.
   */
  async unwrap(options: UnwrapDataKeyOptions): Promise<Uint8Array> {
    const result = await this.#requester.json<unknown>({
      method: 'POST',
      path: `${DATAKEY}/unwrap`,
      body: { wrapped: toBase64(options.wrapped) },
      signal: options.signal,
    })
    return fromBase64(str(record(result.data, 'data'), 'plaintext'))
  }
}
