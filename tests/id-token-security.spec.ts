import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHmac, generateKeyPairSync, sign } from 'node:crypto'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { beginSignIn, type SignInOptions } from '../src/auth/sign-in.ts'
import { validateIdToken, ID_TOKEN_JWKS_URL } from '../src/auth/id-token.ts'
import { ChatGptAuth } from '../src/auth/manager.ts'
import type { ChatGptCredential } from '../src/auth/credential.ts'
import { ChatGptSession } from '../src/session.ts'
import type { ChatGptAdapter } from '../src/adapter.ts'
import { idTokenClaims } from './helpers.ts'

const key = generateKeyPairSync('rsa', { modulusLength: 2048 })
const other = generateKeyPairSync('rsa', { modulusLength: 2048 })
const jwk = { ...key.publicKey.export({ format: 'jwk' }), kid: 'trusted', alg: 'RS256', use: 'sig' }
const rotatedJwk = { ...other.publicKey.export({ format: 'jwk' }), kid: 'rotated', alg: 'RS256', use: 'sig' }
const encode = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url')
function signed(claims: Record<string, unknown>, options: {
  key?: typeof key.privateKey, header?: Record<string, unknown>,
} = {}): string {
  const input = `${encode({ alg: 'RS256', kid: 'trusted', ...options.header })}.${encode(claims)}`
  return `${input}.${sign('RSA-SHA256', Buffer.from(input), options.key ?? key.privateKey).toString('base64url')}`
}
const claimsFor = (nonce = 'nonce') => idTokenClaims({ clientId: 'oaiapp_test', nonce })
const bodyFor = (token: string) => ({
  access_token: 'fixture-access', refresh_token: 'fixture-refresh', expires_in: 3600,
  scope: 'openid chatgpt.tokens.use.direct', id_token: token,
})

/** Drives the real callback -> exchange -> awaited verification -> credential. */
async function login(makeToken: (claims: Record<string, unknown>) => string,
  registration?: SignInOptions['registration']): Promise<ChatGptCredential> {
  let nonce = ''
  const attempt = await beginSignIn({
    agentHostId: 'urn:uuid:test', agentNameHint: 'Test', preferredPort: 0,
    ...registration === undefined ? {} : { registration },
    fetch: async (url) => {
      if (String(url) === ID_TOKEN_JWKS_URL) return Response.json({ keys: [jwk] })
      assert.equal(String(url), 'https://auth.openai.com/api/accounts/oauth/token')
      return Response.json(bodyFor(makeToken(claimsFor(nonce))))
    },
  })
  const params = new URL(attempt.authorizationUrl).searchParams
  nonce = params.get('nonce') ?? ''
  // Attach immediately so a failed exchange cannot become an unhandled rejection.
  const result = attempt.result.then(value => ({ value }), error => ({ error }))
  await attempt.submit(`${attempt.redirectUri}?code=fixture&state=${params.get('state')}&client_id=oaiapp_test`)
  const outcome = await result
  if ('error' in outcome) throw outcome.error
  return outcome.value
}

describe('ID token cryptographic and claim verification at the login call site', () => {
  it('accepts a signed first login without azp and extracts only verified identity', async () => {
    const credential = await login(claims => signed(claims))
    assert.equal(credential.subject, 'subject-1')
    assert.equal(credential.clientId, 'oaiapp_test')
  })
  it('accepts a returning account, audience array, and matching optional azp', async () => {
    const credential = await login(claims => signed({ ...claims, aud: ['oaiapp_test'], azp: 'oaiapp_test' }),
      { clientId: 'oaiapp_test', subject: 'subject-1' })
    assert.equal(credential.subject, 'subject-1')
  })
  it('accepts the official top-level email shape and does not invent a plan', async () => {
    const credential = await login(claims => signed({ ...claims, email: 'official@example.com', email_verified: true,
      'https://api.openai.com/profile': undefined, 'https://api.openai.com/auth': { per_user_salt: 'fixture' } }))
    assert.equal(credential.email, 'official@example.com')
    assert.equal(credential.planType, undefined)
    assert.equal(credential.subject, 'subject-1')
  })
  const attacks: Record<string, (claims: Record<string, unknown>) => string> = {
    'tampered payload': claims => {
      const parts = signed(claims).split('.')
      parts[1] = encode({ ...claims, sub: 'attacker' })
      return parts.join('.')
    },
    'incorrect signature': claims => {
      const parts = signed(claims).split('.')
      parts[2] = Buffer.alloc(256).toString('base64url')
      return parts.join('.')
    },
    'wrong signing key': claims => signed(claims, { key: other.privateKey }),
    'unknown key id': claims => signed(claims, { header: { kid: 'unknown' } }),
    'alg:none': claims => `${encode({ alg: 'none' })}.${encode(claims)}.`,
    'HS256 substitution': claims => {
      const input = `${encode({ alg: 'HS256', kid: 'trusted' })}.${encode(claims)}`
      return `${input}.${createHmac('sha256', Buffer.from(JSON.stringify(jwk))).update(input).digest('base64url')}`
    },
    'malformed JWT': () => 'not.a.jwt',
  }
  for (const [name, make] of Object.entries(attacks)) {
    it(`rejects ${name}`, async () => { await assert.rejects(login(make), /ID token verification failed/) })
  }
  const invalid: Record<string, Record<string, unknown>> = {
    'issuer': { iss: 'https://attacker.invalid' },
    'audience': { aud: 'another-client' },
    'nonce': { nonce: 'another-attempt' },
    'missing nonce': { nonce: undefined },
    'missing subject': { sub: undefined },
    'empty subject': { sub: '   ' },
    'non-string subject': { sub: 123 },
    'missing exp': { exp: undefined },
    'string exp': { exp: '9999999999' },
    'null exp': { exp: null },
    'expired exp': { exp: Math.floor(Date.now() / 1000) - 60, iat: Math.floor(Date.now() / 1000) - 3600 },
    'missing iat': { iat: undefined },
    'string iat': { iat: '0' },
    'null iat': { iat: null },
    'future iat': { iat: Math.floor(Date.now() / 1000) + 60 },
    'future nbf': { nbf: Math.floor(Date.now() / 1000) + 60 },
    'exp before iat': { exp: Math.floor(Date.now() / 1000) + 10, iat: Math.floor(Date.now() / 1000) + 20 },
    'different azp': { azp: 'another-client' },
    'invalid azp': { azp: 123 },
  }
  for (const [name, changes] of Object.entries(invalid)) {
    it(`rejects ${name}`, async () => {
      await assert.rejects(login(claims => signed({ ...claims, ...changes })), /ID token verification failed/)
    })
  }
  it('rejects a different account even when its token is correctly signed', async () => {
    await assert.rejects(login(claims => signed({ ...claims, sub: 'attacker' }),
      { clientId: 'oaiapp_test', subject: 'subject-1' }), /ID token verification failed/)
  })
  it('refuses a substituted returning client before exchanging the code', async () => {
    let calls = 0
    const attempt = await beginSignIn({
      agentHostId: 'test', agentNameHint: 'Test', preferredPort: 0,
      registration: { clientId: 'original-client' },
      fetch: async () => { calls++; throw new Error('must not exchange') },
    })
    const rejected = assert.rejects(attempt.result, /different client id/)
    const state = new URL(attempt.authorizationUrl).searchParams.get('state')
    await attempt.submit(`${attempt.redirectUri}?code=x&state=${state}&client_id=attacker-client`)
    await rejected
    assert.equal(calls, 0)
  })
})

describe('trusted JWKS transport and bounded cache', () => {
  it('ignores token-supplied jku/jwk/x5u and uses only the pinned URL', async () => {
    const urls: string[] = []
    const transport: typeof fetch = async (url, init) => {
      urls.push(String(url))
      assert.equal(init?.redirect, 'manual')
      assert.ok(init?.signal instanceof AbortSignal)
      return Response.json({ keys: [jwk] })
    }
    const token = signed(claimsFor(), { header: { jku: 'https://attacker.invalid/jwks', x5u: 'https://attacker.invalid/cert', jwk: rotatedJwk } })
    await validateIdToken(token, 'oaiapp_test', 'nonce', { fetch: transport })
    assert.deepEqual(urls, [ID_TOKEN_JWKS_URL])
  })
  it('coalesces concurrent requests, reuses cache, rotates keys, and expires cache', async (t) => {
    let now = Date.now()
    t.mock.method(Date, 'now', () => now)
    let calls = 0
    let keys = [jwk]
    const transport: typeof fetch = async () => { calls++; return Response.json({ keys }) }
    const first = signed(claimsFor())
    await Promise.all(Array.from({ length: 4 }, () => validateIdToken(first, 'oaiapp_test', 'nonce', { fetch: transport })))
    assert.equal(calls, 1)
    await validateIdToken(first, 'oaiapp_test', 'nonce', { fetch: transport })
    assert.equal(calls, 1)
    now += 31_000
    keys = [rotatedJwk]
    const rotated = signed(claimsFor(), { key: other.privateKey, header: { kid: 'rotated' } })
    await validateIdToken(rotated, 'oaiapp_test', 'nonce', { fetch: transport })
    assert.equal(calls, 2)
    now += 601_000
    await validateIdToken(rotated, 'oaiapp_test', 'nonce', { fetch: transport })
    assert.equal(calls, 3)
  })
  it('rate limits unknown-key refreshes during cooldown', async () => {
    let calls = 0
    const transport: typeof fetch = async () => { calls++; return Response.json({ keys: [jwk] }) }
    await validateIdToken(signed(claimsFor()), 'oaiapp_test', 'nonce', { fetch: transport })
    for (let index = 0; index < 3; index++) {
      await assert.rejects(validateIdToken(signed(claimsFor(), { header: { kid: `unknown-${index}` } }),
        'oaiapp_test', 'nonce', { fetch: transport }), /ID token verification failed/)
    }
    assert.equal(calls, 1)
  })
  it('propagates the five-second JWKS deadline into the existing fetch transport', async () => {
    let aborted = false
    const transport: typeof fetch = async (_url, init) => new Promise<Response>((_resolve, reject) => {
      // The guard holds the event loop alive; it must not be what fails verification.
      const guard = setTimeout(() => reject(new Error('test guard reached')), 8_000)
      init?.signal?.addEventListener('abort', () => {
        aborted = true
        clearTimeout(guard)
        reject(init.signal?.reason)
      }, { once: true })
    })
    await assert.rejects(validateIdToken(signed(claimsFor()), 'oaiapp_test', 'nonce', { fetch: transport }), /ID token verification failed/)
    assert.equal(aborted, true)
  })
  for (const failure of ['network', 'HTTP', 'malformed JWKS']) {
    it(`fails closed and sanitizes ${failure} errors`, async () => {
      const transport: typeof fetch = async () => {
        if (failure === 'network') throw new Error('fixture-access fixture-refresh fixture-id callback?code=fixture')
        if (failure === 'HTTP') return new Response('fixture-access', { status: 503 })
        return Response.json({ keys: 'not keys' })
      }
      await assert.rejects(validateIdToken(signed(claimsFor()), 'oaiapp_test', 'nonce', { fetch: transport }), error => {
        assert.ok(error instanceof Error)
        assert.match(error.message, /ID token verification failed/)
        assert.doesNotMatch(error.message, /fixture-|callback\?/)
        return true
      })
    })
  }
})

describe('session persistence and returning identity binding', () => {
  for (const failure of ['JWKS', 'signature', 'subject', 'client', 'transport']) {
    it(`${failure} failure preserves the existing account byte-for-byte`, async () => {
      const dir = await mkdtemp(join(tmpdir(), 'chatgpt-verified-login-'))
      try {
        let nonce = ''
        let requestedClient = ''
        const auth = new ChatGptAuth({
          stateDir: dir, agentNameHint: 'Test', endpoints: { preferredPort: 0 },
          fetch: async (url) => {
            if (String(url) === ID_TOKEN_JWKS_URL) {
              if (failure === 'JWKS') throw new Error('fixture-access')
              return Response.json({ keys: [jwk] })
            }
            if (failure === 'transport') throw new Error('fixture-access fixture-refresh fixture-id full-callback')
            return Response.json(bodyFor(signed({ ...claimsFor(nonce), sub: failure === 'subject' ? 'different' : 'subject-1' },
              failure === 'signature' ? { key: other.privateKey } : {})))
          },
        })
        auth.adopt({ accessToken: 'old-access', refreshToken: 'old-refresh', clientId: 'oaiapp_test',
          subject: 'subject-1', scopes: ['chatgpt.tokens.use.direct'], expiresAt: Date.now() + 3600_000, savedAt: Date.now() })
        const before = await readFile(auth.storePath, 'utf8')
        const adapter = { forgetListing() { assert.fail('failed login invalidated listing') }, listModels: async () => [] } as unknown as ChatGptAdapter
        const session = new ChatGptSession(auth, adapter)
        const opened = await session.begin()
        const params = new URL(opened.pending?.url ?? '').searchParams
        nonce = params.get('nonce') ?? ''
        requestedClient = params.get('client_id') ?? ''
        assert.equal(requestedClient, 'oaiapp_test')
        const status = await session.submit(`${opened.pending?.redirectUri}?code=fixture&state=${params.get('state')}&client_id=${failure === 'client' ? 'different-client' : 'oaiapp_test'}`)
        assert.ok(status.error)
        assert.doesNotMatch(status.error, /fixture-|full-callback/)
        assert.equal(auth.active()?.accessToken, 'old-access')
        assert.equal(await readFile(auth.storePath, 'utf8'), before)
      } finally {
        assert.ok(resolve(dir).startsWith(resolve(tmpdir(), 'chatgpt-verified-login-')))
        await rm(dir, { recursive: true, force: true })
      }
    })
  }
  it('persists a verified login, survives reopen, and binds the retained subject after local sign-out', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'chatgpt-verified-login-'))
    try {
      let nonce = ''
      let subject = 'subject-1'
      const transport: typeof fetch = async (url) => String(url) === ID_TOKEN_JWKS_URL
        ? Response.json({ keys: [jwk] })
        : Response.json(bodyFor(signed({ ...claimsFor(nonce), sub: subject })))
      const options = { stateDir: dir, agentNameHint: 'Test', fetch: transport, endpoints: { preferredPort: 0 } }
      const auth = new ChatGptAuth(options)
      const adapter = { forgetListing() {}, listModels: async () => [] } as unknown as ChatGptAdapter
      const session = new ChatGptSession(auth, adapter)
      for (let index = 0; index < 2; index++) {
        const opened = await session.begin()
        const params = new URL(opened.pending?.url ?? '').searchParams
        assert.equal(params.get('client_id'), index === 0 ? 'dynamic_agent_client' : 'oaiapp_test')
        nonce = params.get('nonce') ?? ''
        const result = await session.submit(`${opened.pending?.redirectUri}?code=fixture&state=${params.get('state')}&client_id=oaiapp_test`)
        assert.equal(result.error, undefined)
        assert.equal(result.signedIn, true)
      }
      const reopened = new ChatGptAuth({ ...options, fetch: async () => { throw new Error('fresh credentials need no network') } })
      assert.equal((await reopened.usable()).subject, 'subject-1')
      // Test-only local removal: do not revoke an external account.
      auth.signOut()
      const before = await readFile(auth.storePath, 'utf8')
      const opened = await session.begin()
      const params = new URL(opened.pending?.url ?? '').searchParams
      assert.equal(params.get('client_id'), 'oaiapp_test')
      nonce = params.get('nonce') ?? ''
      subject = 'different-account'
      const status = await session.submit(`${opened.pending?.redirectUri}?code=fixture&state=${params.get('state')}&client_id=oaiapp_test`)
      assert.match(status.error ?? '', /ID token verification failed/)
      assert.equal(auth.active(), undefined)
      assert.equal(await readFile(auth.storePath, 'utf8'), before)
    } finally {
      assert.ok(resolve(dir).startsWith(resolve(tmpdir(), 'chatgpt-verified-login-')))
      await rm(dir, { recursive: true, force: true })
    }
  })
  it('does not infer a subject from a synthetic local account key or email', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'chatgpt-verified-login-'))
    try {
      const auth = new ChatGptAuth({ stateDir: dir, agentNameHint: 'Test', endpoints: { preferredPort: 0 } })
      const localKey = auth.adopt({ accessToken: 'fixture', refreshToken: 'fixture', clientId: 'oaiapp_test',
        scopes: ['chatgpt.tokens.use.direct'], expiresAt: Date.now() + 3600_000, email: 'someone@example.com', savedAt: Date.now() })
      assert.match(localKey, /^account-/)
      auth.signOut()
      const attempt = await auth.begin()
      assert.equal(new URL(attempt.authorizationUrl).searchParams.get('client_id'), 'oaiapp_test')
      attempt.cancel()
      await assert.rejects(attempt.result)
      const persisted = JSON.parse(await readFile(auth.storePath, 'utf8'))
      assert.equal(persisted.registrations[localKey].subject, undefined)
    } finally {
      assert.ok(resolve(dir).startsWith(resolve(tmpdir(), 'chatgpt-verified-login-')))
      await rm(dir, { recursive: true, force: true })
    }
  })
})
