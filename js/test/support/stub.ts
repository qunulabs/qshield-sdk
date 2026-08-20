/**
 * A qshield stand-in that runs inside the test process.
 *
 * Plain HTTP on the loopback address, which the client allows precisely because
 * that is what local development uses. The one test that needs TLS starts its
 * own server with the committed test-only certificate.
 */

import { readFileSync } from 'node:fs'
import http from 'node:http'
import https from 'node:https'
import type { AddressInfo } from 'node:net'
import path from 'node:path'

/** What the stub recorded about one request it received. */
export interface Recorded {
  readonly method: string
  readonly path: string
  readonly headers: http.IncomingHttpHeaders
  readonly body: string
}

/** How a test answers one request. */
export type Responder = (
  request: Recorded,
  response: http.ServerResponse,
  index: number,
) => void | Promise<void>

export interface Stub {
  readonly baseUrl: string
  readonly requests: Recorded[]
  close(): Promise<void>
}

async function listen(server: http.Server | https.Server, scheme: string): Promise<string> {
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', resolve)
  })
  const { port } = server.address() as AddressInfo
  return `${scheme}://127.0.0.1:${port}`
}

function attach(
  server: http.Server | https.Server,
  respond: Responder,
  requests: Recorded[],
): void {
  server.on('request', (req, res) => {
    const chunks: Buffer[] = []
    req.on('data', (chunk: Buffer) => chunks.push(chunk))
    req.on('end', () => {
      const recorded: Recorded = {
        method: req.method ?? '',
        path: req.url ?? '',
        headers: req.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      }
      const index = requests.length
      requests.push(recorded)
      void Promise.resolve(respond(recorded, res, index)).catch(() => {
        res.statusCode = 500
        res.end()
      })
    })
  })
}

function closer(server: http.Server | https.Server): () => Promise<void> {
  return () =>
    new Promise<void>((resolve) => {
      server.closeAllConnections()
      server.close(() => {
        resolve()
      })
    })
}

/** Starts a plain stub and returns its address. */
export async function startStub(respond: Responder): Promise<Stub> {
  const requests: Recorded[] = []
  const server = http.createServer()
  attach(server, respond, requests)
  const baseUrl = await listen(server, 'http')
  return { baseUrl, requests, close: closer(server) }
}

// Resolved from the package root, because the tests are compiled into a
// separate output directory before they run.
const fixtures = path.join(process.cwd(), 'test', 'fixtures')

/**
 * Starts a stub behind TLS, using the committed test-only self-signed
 * certificate. Nothing trusts it, which is the whole point of the test that
 * uses it.
 */
export async function startUntrustedTlsStub(respond: Responder): Promise<Stub> {
  const requests: Recorded[] = []
  const server = https.createServer({
    cert: readFileSync(path.join(fixtures, 'test-only-untrusted-cert.pem')),
    key: readFileSync(path.join(fixtures, 'test-only-untrusted-key.pem')),
  })
  attach(server, respond, requests)
  const baseUrl = await listen(server, 'https')
  return { baseUrl, requests, close: closer(server) }
}

/** Writes a platform-envelope success. */
export function ok(
  res: http.ServerResponse,
  data: unknown,
  extra: Record<string, unknown> = {},
): void {
  res.setHeader('content-type', 'application/json')
  res.setHeader('x-request-id', 'req-test-1')
  res.statusCode = 200
  res.end(JSON.stringify({ success: true, data, request_id: 'req-test-1', ...extra }))
}

/** Writes a platform-envelope success with a 201, as a creation route answers. */
export function created(res: http.ServerResponse, data: unknown): void {
  res.setHeader('content-type', 'application/json')
  res.setHeader('x-request-id', 'req-test-1')
  res.statusCode = 201
  res.end(JSON.stringify({ success: true, data, request_id: 'req-test-1' }))
}

/**
 * Writes a bare 204: no envelope, no content type, no body.
 *
 * Deleting a vault key is the one route in that tree that answers this way, and
 * a stub that quietly wrote an envelope instead would prove nothing about it.
 */
export function noContent(res: http.ServerResponse): void {
  res.statusCode = 204
  res.end()
}

/** Writes a platform-envelope failure. */
export function fail(
  res: http.ServerResponse,
  status: number,
  error: {
    code?: string
    message?: string
    description?: string
    details?: Record<string, string>
  },
): void {
  res.setHeader('content-type', 'application/json')
  res.setHeader('x-request-id', 'req-test-err')
  res.statusCode = status
  res.end(JSON.stringify({ success: false, error, request_id: 'req-test-err' }))
}

/**
 * Writes the flat token-grant success.
 *
 * `extra` carries the version fields qshield adds to this response, so a test
 * can describe a deployment without a second route.
 */
export function token(
  res: http.ServerResponse,
  accessToken: string,
  expiresIn = 900,
  extra: Record<string, unknown> = {},
): void {
  res.setHeader('content-type', 'application/json')
  res.statusCode = 200
  res.end(
    JSON.stringify({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: expiresIn,
      ...extra,
    }),
  )
}

/** Writes the flat token-grant failure, in the shape the route now sends. */
export function tokenError(
  res: http.ServerResponse,
  status: number,
  error: string,
  description: string,
  code?: string,
): void {
  res.setHeader('content-type', 'application/json')
  res.statusCode = status
  res.end(
    JSON.stringify({
      error,
      error_description: description,
      ...(code === undefined ? {} : { error_code: code }),
    }),
  )
}

/** A syntactically valid credential. It authenticates against the stub only. */
export const CREDENTIAL = {
  clientId: 'qsc_abcdefghijklmnopqrstuv',
  clientSecret: 'qss_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG',
}
