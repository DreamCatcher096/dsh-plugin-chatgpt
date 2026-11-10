/** OpenAI ID tokens are trusted only after verification against its pinned JWKS. */
import { createRemoteJWKSet, customFetch, jwtVerify } from 'jose'

export const ID_TOKEN_ISSUER = 'https://auth.openai.com'
export const ID_TOKEN_JWKS_URL = 'https://auth.openai.com/.well-known/jwks.json'
const CLOCK_TOLERANCE_SECONDS = 5

// One resolver per transport, shared across attempts. Weak keys do not retain a
// disposed plugin's proxy dispatcher. jose bounds cache age, coalesces fetches,
// and re-fetches unknown keys after the cooldown to support key rotation.
const resolvers = new WeakMap<typeof fetch, ReturnType<typeof createRemoteJWKSet>>()
function resolverFor(transport: typeof fetch): ReturnType<typeof createRemoteJWKSet> {
  let resolver = resolvers.get(transport)
  if (resolver === undefined) {
    resolver = createRemoteJWKSet(new URL(ID_TOKEN_JWKS_URL), {
      [customFetch]: transport,
      timeoutDuration: 5_000,
      cooldownDuration: 30_000,
      cacheMaxAge: 600_000,
    })
    resolvers.set(transport, resolver)
  }
  return resolver
}

export class IdTokenVerificationError extends Error {
  constructor() {
    super('ChatGPT ID token verification failed: invalid signature or identity claims, or trusted JWKS unavailable')
  }
}

export interface VerifiedIdentity {
  subject: string
  email?: string
  planType?: string
}

/**
 * Verify before exposing identity or allowing a credential to be saved.
 * Neither the JWT header nor any callback can select an issuer, key, or URL.
 * Errors intentionally omit the JWT, claims, callback, and transport exception.
 */
export async function validateIdToken(
  token: string,
  expectedAudience: string,
  expectedNonce: string,
  options: { fetch?: typeof fetch, subject?: string } = {},
): Promise<VerifiedIdentity> {
  try {
    if (expectedAudience.trim().length === 0 || expectedNonce.trim().length === 0) throw new Error()
    const { payload: claims } = await jwtVerify(token, resolverFor(options.fetch ?? globalThis.fetch), {
      algorithms: ['RS256'],
      issuer: ID_TOKEN_ISSUER,
      audience: expectedAudience,
      requiredClaims: ['sub', 'exp', 'iat', 'nonce'],
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
    })
    if (typeof claims.sub !== 'string' || claims.sub.trim().length === 0) throw new Error()
    if (claims.nonce !== expectedNonce) throw new Error()
    if (options.subject !== undefined && claims.sub !== options.subject) throw new Error()
    if (claims.azp !== undefined && claims.azp !== expectedAudience) throw new Error()
    if (typeof claims.exp !== 'number' || !Number.isFinite(claims.exp)
      || typeof claims.iat !== 'number' || !Number.isFinite(claims.iat)
      || claims.iat > Date.now() / 1000 + CLOCK_TOLERANCE_SECONDS
      || claims.exp <= claims.iat) throw new Error()

    const profile = claims['https://api.openai.com/profile']
    const auth = claims['https://api.openai.com/auth']
    // The official example uses a top-level email; keep the legacy namespace
    // as a display/login-hint fallback only, never as an identity binding.
    const email = typeof claims.email === 'string' && claims.email.length > 0
      ? claims.email
      : typeof profile === 'object' && profile !== null
        ? (profile as Record<string, unknown>)['email'] : undefined
    const planType = typeof auth === 'object' && auth !== null
      ? (auth as Record<string, unknown>)['chatgpt_plan_type'] : undefined
    return {
      subject: claims.sub,
      ...typeof email === 'string' && email.length > 0 ? { email } : {},
      ...typeof planType === 'string' && planType.length > 0 ? { planType } : {},
    }
  } catch {
    throw new IdTokenVerificationError()
  }
}
