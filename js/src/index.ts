/**
 * @qnulabs/qshield-sdk
 *
 * A typed client for the qshield API, authenticated as a service account.
 *
 * This phase publishes the client and its options only. The product namespaces
 * arrive in later phases as properties of the client. Nothing about the
 * transport underneath is exported, deliberately: every exported name is a
 * promise this package keeps for as long as it exists.
 *
 * The SDK assumes the machine and the application that host it already have
 * network access to qshield and already trust the certificate authority that
 * issued its certificate. It changes neither. If either is missing, the call
 * fails with an error that says which one and how to fix it.
 */

export { QShieldClient } from './client.js'
export type { QShieldClientOptions, VersionCheck, WarningHandler } from './internal/config.js'

/**
 * The failures. Every one of them descends from QShieldError, so a caller that
 * catches the base class catches everything this package can throw, and one that
 * wants to branch can test for the kind it knows how to handle.
 *
 * The whole set is published rather than the handful the first namespace raises,
 * because which failure a route can produce is not something a caller should
 * have to discover from an SDK release note. Each class carries the catalogue
 * code, the operator message, the developer description, whatever the failure
 * named, and the qshield request identifier to quote to support.
 */
export {
  QShieldError,
  AuthenticationError,
  PermissionError,
  HumanOnlyError,
  NotLicensedError,
  VaultSealedError,
  RequestError,
  ValidationError,
  NotFoundError,
  ConflictError,
  GoneError,
  RateLimitError,
  ServerError,
  ConfigurationError,
  ConnectionError,
  TimeoutError,
  CancelledError,
  ProtocolError,
  TimeKeyNotYetValidError,
  TimeKeyExpiredError,
  TimeKeyPassphraseRejectedError,
} from './internal/errors.js'
export type { QShieldErrorFields } from './internal/errors.js'

/**
 * QuantumVault.
 *
 * The namespaces themselves are exported as types only: a caller reaches them
 * through a client, never by constructing one, so publishing the constructors
 * would only create a way to build something that cannot work.
 */
export type { VaultNamespace } from './vault/index.js'
export type { KeysNamespace } from './vault/keys.js'
export type { DataKeysNamespace } from './vault/datakeys.js'
export type { TimeConstrainedKeysNamespace } from './vault/timekeys.js'
export type {
  CreateKeyOptions,
  DecapsulateOptions,
  DecryptOptions,
  DeleteKeyOptions,
  EncapsulateOptions,
  EncryptOptions,
  GetKeyOptions,
  HmacOptions,
  KeyPublicKeyOptions,
  KeyVersionsOptions,
  ListKeysOptions,
  RotateKeyOptions,
  SignOptions,
  VerifyOptions,
} from './vault/keys.js'
export type { GenerateDataKeyOptions, UnwrapDataKeyOptions } from './vault/datakeys.js'
export type {
  CreateTimeConstrainedKeyOptions,
  DestroyTimeConstrainedKeyOptions,
  ExtendTimeConstrainedKeyOptions,
  GetTimeConstrainedKeyOptions,
  ListTimeConstrainedKeysOptions,
  TimeKeyDecapsulateOptions,
  TimeKeyDecryptOptions,
  TimeKeyEncapsulateOptions,
  TimeKeyEncryptOptions,
  TimeKeyPublicKeyOptions,
} from './vault/timekeys.js'
export type {
  DataKey,
  EncapsulateResult,
  EncryptResult,
  HmacResult,
  Key,
  KeyCloudOrigin,
  KeyOrigin,
  KeyPublicKey,
  KeyPurpose,
  KeyState,
  KeyVersion,
  KeyVersions,
  SignResult,
  CreatedTimeConstrainedKey,
  TimeConstrainedKey,
  TimeKeyEncapsulation,
  TimeKeyPublicKey,
  TimeKeyWindowStatus,
} from './vault/types.js'
export { KNOWN_KEY_ALGORITHMS } from './vault/algorithms.js'
export type { KeyAlgorithmId, KnownKeyAlgorithmId } from './vault/algorithms.js'
