/**
 * The codes the SDK issues for failures it detects itself.
 *
 * qshield answers every failure with a catalogue code, an operator message and
 * a developer description. Some failures never reach qshield at all: the
 * address does not resolve, the connection is refused, the server's certificate
 * is not trusted by this process, the request timed out. The server said
 * nothing about those, so the SDK says it, in the same four parts, and a caller
 * handles one error shape whatever went wrong.
 *
 * The area marker is SD, which the platform catalogue does not use and never
 * will, so an SDK code can never be mistaken for one qshield sent. A code here
 * is a permanent promise exactly as a catalogue code is: never renumber one,
 * never reuse a retired number, and never change what one means.
 *
 * The two messages follow the platform's rule and must stay genuinely
 * different. The OPERATOR message names what happened and the next action in
 * the customer's own terms. The DEVELOPER message names the setting, the
 * address or the host condition to change.
 */

/** One entry: the four parts every SDK-raised failure carries. */
export interface CodeEntry {
  /** The stable code, for example "ESD-003". */
  readonly code: string
  /** A short stable name for the failure, matching the platform's slug style. */
  readonly slug: string
  /** What happened and what to do about it, for the person running the app. */
  readonly operator: string
  /** What to change, for whoever wrote or deployed the app. */
  readonly developer: string
}

/**
 * The client was handed something it cannot use. Raised before any request
 * leaves the process.
 */
export const ClientConfigurationInvalid: CodeEntry = {
  code: 'ESD-001',
  slug: 'client-configuration-invalid',
  operator:
    'This application is not configured correctly for qshield, so it did not try to connect. Check the qshield address and the credential it was given.',
  developer:
    'A value passed to the client constructor is missing or malformed. The failure names the field. The address must be an absolute https URL, or an http URL on the local machine for development. The client id begins with qsc_ and the client secret with qss_.',
}

/** The host name in the configured address does not resolve. */
export const AddressUnresolvable: CodeEntry = {
  code: 'ESD-002',
  slug: 'address-unresolvable',
  operator:
    'The qshield address could not be found on the network, so this application cannot reach it. Check the address, and check that this machine uses a name server that knows it.',
  developer:
    'DNS resolution failed for the host in the configured base URL. Correct the host name, or make the name resolvable from this machine. An internal qshield address usually resolves only on the internal network or through a split-horizon resolver.',
}

/** The connection could not be established. */
export const ConnectionFailed: CodeEntry = {
  code: 'ESD-003',
  slug: 'connection-failed',
  operator:
    'This application could not open a connection to qshield. Check that qshield is running and that this machine is allowed to reach it.',
  developer:
    'The TCP connection to the configured base URL could not be established. Confirm the host and port, that anything in front of qshield is accepting connections, and that outbound access to that port is permitted from this machine.',
}

/** The server presented a certificate this process does not trust. */
export const ServerCertificateUntrusted: CodeEntry = {
  code: 'ESD-004',
  slug: 'server-certificate-untrusted',
  operator:
    'This application reached qshield but did not trust its certificate, so it closed the connection. The certificate authority that issued it must be trusted by this machine and by this application.',
  developer:
    'TLS verification failed. Node does not read the operating system trust store by default, so an internal root installed on the machine is ignored: start this process with --use-system-ca, or point NODE_EXTRA_CA_CERTS at the internal root certificate file. The SDK deliberately offers no option to supply a certificate authority or to skip verification.',
}

/** The request was sent, or attempted, and no response arrived in time. */
export const RequestTimedOut: CodeEntry = {
  code: 'ESD-005',
  slug: 'request-timed-out',
  operator:
    'qshield did not answer in time, so this application stopped waiting. The action may or may not have been carried out. Check in qshield before trying again.',
  developer:
    'No response arrived within the configured request timeout. Raise the timeout on the client if the operation is genuinely slow. The SDK does not repeat a timed-out request that changes state, because repeating one can perform the action twice.',
}

/** The caller cancelled the request. */
export const RequestCancelled: CodeEntry = {
  code: 'ESD-006',
  slug: 'request-cancelled',
  operator: 'The request to qshield was cancelled before it finished.',
  developer:
    'The abort signal passed to this call was triggered. Nothing was retried and no further request was made. Whether qshield completed the work is undefined, exactly as for any cancelled request.',
}

/** The response did not have the shape qshield is defined to send. */
export const ResponseNotUnderstood: CodeEntry = {
  code: 'ESD-007',
  slug: 'response-not-understood',
  operator:
    'qshield answered with something this application could not read. Check that the configured address points at qshield itself and not at something in front of it.',
  developer:
    'The response body was not the JSON envelope this endpoint is defined to return. A proxy error page, a captive portal or a sign-in redirect produces this. Confirm the base URL reaches qshield directly, and that the SDK version matches the qshield version.',
}

/** Every entry, for the guard that proves the block is well formed. */
export const sdkCodes: readonly CodeEntry[] = [
  ClientConfigurationInvalid,
  AddressUnresolvable,
  ConnectionFailed,
  ServerCertificateUntrusted,
  RequestTimedOut,
  RequestCancelled,
  ResponseNotUnderstood,
]
