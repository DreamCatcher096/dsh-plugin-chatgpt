/**
 * Test doubles: a token endpoint, an RS256-signed ID token, the JWK Set that
 * verifies it, and a transport that answers the one JWKS URL sign-in fetches.
 *
 * The ID token is genuinely signed. Sign-in verifies every ID token against
 * OpenAI's published JWKS, fetched over the injected transport, so a fixture
 * that were merely base64url-encoded would drive each success test down the
 * rejection path. The key pair is generated once per test process with
 * `node:crypto`, and its public half is exported as {@link fixtureJwks} for a
 * transport to serve in place of the real `jwks_uri`.
 */

import { createServer, type Server } from 'node:http'
import assert from 'node:assert/strict'
import { generateKeyPairSync, sign as signData } from 'node:crypto'

/** Narrow an expected fixture element with a real runtime assertion. */
export function required<T>(value: T | undefined): T {
  assert.ok(value !== undefined, 'expected a fixture value')
  return value
}

/** One request the token endpoint received. */
export interface RecordedRequest {
  path: string
  contentType: string
  params: URLSearchParams
}

/** A live token endpoint and the requests it saw. */
export interface TokenServer {
  url: string
  requests: RecordedRequest[]
  close(): Promise<void>
}

/** The one JWKS URL an ID-token verification may fetch. */
export const OPENAI_JWKS_URL = 'https://auth.openai.com/.well-known/jwks.json'

/** The `kid` these fixtures publish and sign under. */
const FIXTURE_KID = 'test-rs256'

/** One RSA key pair for the whole test process; the private half stays here. */
const fixtureKeys = generateKeyPairSync('rsa', { modulusLength: 2048 })

/** The RFC 7517 document OpenAI's `jwks_uri` answers with for these fixtures. */
export const fixtureJwks = {
  keys: [{
    ...fixtureKeys.publicKey.export({ format: 'jwk' }),
    alg: 'RS256',
    use: 'sig',
    kid: FIXTURE_KID,
  }],
}

/**
 * Build an RS256-signed JWT whose payload carries `claims`.
 *
 * Signing is synchronous so fixtures stay buildable at call sites, and the
 * signature is real: it is what a verifier keyed by {@link fixtureJwks}
 * accepts.
 *
 * @param claims - the JWT Claims Set to carry verbatim.
 * @returns the compact JWS serialization.
 */
export function jwt(claims: Record<string, unknown>): string {
  const encode = (value: unknown): string =>
    Buffer.from(JSON.stringify(value), 'utf8').toString('base64url')
  const signingInput = `${encode({ alg: 'RS256', typ: 'JWT', kid: FIXTURE_KID })}.${encode(claims)}`
  const signature = signData('RSA-SHA256', Buffer.from(signingInput, 'utf8'), fixtureKeys.privateKey)
  return `${signingInput}.${signature.toString('base64url')}`
}

/** The URL a fetch-like input addresses, in whichever shape it arrived. */
export function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input
  if (input instanceof URL) return input.href
  return input.url
}

/**
 * Wrap a transport so the fixed OpenAI JWKS URL answers from {@link fixtureJwks}.
 *
 * The interception is deliberately narrow: only that one URL is answered
 * locally, and every other request — the code exchange, discovery, revocation —
 * still travels over `transport`, which is what lets the proxy suite see the
 * tunnel. A test that forgets this wrapper reaches the real network instead of
 * silently verifying against nothing.
 *
 * @param transport - the transport every non-JWKS request still uses.
 * @returns a fetch that serves the fixture key set and delegates the rest.
 */
export function withJwks(transport: typeof fetch = globalThis.fetch): typeof fetch {
  return ((input: RequestInfo | URL, init?: RequestInit) => {
    if (requestUrl(input) !== OPENAI_JWKS_URL) return transport(input, init)
    return Promise.resolve(Response.json(fixtureJwks))
  }) as typeof fetch
}

/** ID-token claims addressing one issued client id and nonce. */
export function idTokenClaims(options: {
  clientId: string
  nonce: string
  subject?: string
  email?: string
  plan?: string
  expiresInSeconds?: number
  issuer?: string
}): Record<string, unknown> {
  return {
    iss: options.issuer ?? 'https://auth.openai.com',
    aud: options.clientId,
    sub: options.subject ?? 'subject-1',
    nonce: options.nonce,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (options.expiresInSeconds ?? 3600),
    'https://api.openai.com/profile': { email: options.email ?? 'someone@example.com' },
    'https://api.openai.com/auth': { chatgpt_plan_type: options.plan ?? 'plus' },
  }
}

/** A token response the mock endpoint returns. */
export interface TokenReply {
  status?: number
  body?: unknown
  /** Read the request and answer dynamically (nonce must match the attempt). */
  reply?: (params: URLSearchParams) => { status?: number, body: unknown }
}

/**
 * Start a token endpoint answering every request with `reply`.
 *
 * @param reply - the response, or a function of the received form fields.
 * @returns the endpoint, its recorded requests, and a closer.
 */
export async function startTokenServer(reply: TokenReply): Promise<TokenServer> {
  const requests: RecordedRequest[] = []
  const server: Server = createServer((request, response) => {
    let body = ''
    request.setEncoding('utf8')
    request.on('data', (chunk: string) => { body += chunk })
    request.on('end', () => {
      const params = new URLSearchParams(body)
      requests.push({
        path: request.url ?? '/',
        contentType: String(request.headers['content-type'] ?? ''),
        params,
      })
      const answer = reply.reply?.(params) ?? { status: reply.status, body: reply.body }
      response.writeHead(answer.status ?? 200, { 'content-type': 'application/json' })
      response.end(JSON.stringify(answer.body))
    })
  })
  await new Promise<void>(resolve => { server.listen(0, '127.0.0.1', resolve) })
  const address = server.address()
  if (address === null || typeof address === 'string') throw new Error('token server bound no port')
  return {
    url: `http://127.0.0.1:${address.port}/token`,
    requests,
    close: () => new Promise<void>((resolve, reject) => {
      server.close(error => { error === undefined ? resolve() : reject(error) })
      server.closeAllConnections()
    }),
  }
}

/** Resolve once `check` passes, or reject after `timeoutMs`. */
export async function waitFor(check: () => boolean, timeoutMs = 2000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (!check()) {
    if (Date.now() > deadline) throw new Error('waitFor timed out')
    await new Promise(resolve => setTimeout(resolve, 10))
  }
}
