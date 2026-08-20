/**
 * `client.vault` - QuantumVault.
 *
 * A namespace per resource kind rather than one flat surface, so a domain added
 * later cannot collide with one already published.
 */

import { DataKeysNamespace } from './datakeys.js'
import type { Requester } from '../internal/requester.js'
import { KeysNamespace } from './keys.js'
import { TimeConstrainedKeysNamespace } from './timekeys.js'

/** QuantumVault. Reached as `client.vault`. */
export class VaultNamespace {
  /** The keys in your workspace. */
  readonly keys: KeysNamespace
  /** Data keys for encrypting your own data. */
  readonly dataKeys: DataKeysNamespace
  /** Keys that only work between two moments, and are destroyed after. */
  readonly timeConstrainedKeys: TimeConstrainedKeysNamespace

  constructor(requester: Requester) {
    this.keys = new KeysNamespace(requester)
    this.dataKeys = new DataKeysNamespace(requester)
    this.timeConstrainedKeys = new TimeConstrainedKeysNamespace(requester)
  }
}
