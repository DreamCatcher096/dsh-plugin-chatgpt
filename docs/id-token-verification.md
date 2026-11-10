# ID-token verification in 0.1.18-allen.1

This fork fixes the ID-token verification gap in upstream 0.1.18
(commit `885ca6534dfd3b5c0ee5a7aa7a7bc35b198869fc`). It is not an OpenAI
certification, a complete security audit, or a change to the subscription API.

## Trust and ordering

`beginSignIn()` awaits `validateIdToken()` before resolving its credential.
The session adopts and saves only a successful result. The verifier uses
`jose`'s `jwtVerify` and `createRemoteJWKSet`, with the following pinned trust
configuration, checked against official discovery on 2026-11-10:

- issuer: `https://auth.openai.com`
- JWKS: `https://auth.openai.com/.well-known/jwks.json`
- algorithms: `RS256` only
- audience: the issued client ID (never `dynamic_agent_client`)
- required: non-empty string `sub`, `nonce`, numeric finite `exp` and `iat`
- expiration and optional `nbf`: jose's checks, with five seconds of clock tolerance
- `iat`: not more than five seconds in the future; `exp` must follow `iat`
- nonce: exact match to this attempt
- `azp`: if present, exact match to the issued client; not mandatory for every token

JWT headers such as `jku`, `jwk`, and `x5u` cannot select a trust source.
Discovery is not fetched dynamically at login: a changed trust configuration
requires a reviewed code update rather than silently expanding the trust set.
There is no production bypass or decode-only fallback.

## Returning identity

A returning callback may omit `client_id`, but cannot replace the stored one.
If the original credential's real `subject` is known, the new token must match.
New retained registrations explicitly preserve that subject after sign-out.
Signing out an existing legacy account also preserves its known credential
subject before deleting the credential. Legacy registrations with no remaining
credential and no subject remain readable, but a subject is never
invented from an email or from a synthetic `account-*` local key. A successful
verified login supplies it for future attempts. This does not retroactively
verify old credentials; installation acceptance must include a fresh browser
sign-in, not just refreshing an old token.

The existing sign-in UI reuses an active or most recently retained registration.
It must therefore return to that registered account, not silently change it.
Adding an unrelated account needs a distinct, explicitly selected registration
flow; this scoped patch does not add a new account-management UI. Email is only
a verified-token display/login hint, never proof of account ownership. Plan
metadata remains optional; an absent plan claim is not inferred from another
token. Pre-existing replay-namespace migration can still write legacy state on
first load; the failure byte-for-byte tests use already initialized documents.

## Network and cache

JWKS uses exactly the injected plugin fetch, including `createScopedFetch`'s
private proxy dispatcher, redirect handling, and AbortSignal. One shared remote
resolver per transport coalesces requests. Its in-memory cache is valid for
600 seconds, unknown-key reloads are rate-limited by a 30-second cooldown, and
network operations have a five-second timeout. Rotation to a new `kid` inside
the cooldown fails closed; retry after the cooldown. JWKS is not persisted.
A disposed transport is not kept alive by the resolver map's weak keys.

JWKS failure, malformed keys, invalid claims, and bad signatures fail the
attempt. Errors do not include raw server error bodies, callbacks, claims, or
credentials. The browser callback page says authorization was received, not
that verification has already succeeded.

## Validation

The security tests drive the real sign-in call site and the session persistence
path with generated 2048-bit RSA keys and synthetic credentials. Existing success
fixtures are also RS256-signed. A local CONNECT proxy test carries both code
exchange and JWKS retrieval through `createScopedFetch`. Cache coalescing,
expiry, cooldown, rotation, timeout propagation, and failure preserving an
existing credential file are covered. No real account state is needed.

The provider interface, model request conversion, replay/cache namespaces,
refresh behavior, and revocation path are otherwise unchanged.

## References

- https://developers.openai.com/siwc/token-sharing-open-source/sign-in
- https://developers.openai.com/siwc/website
- https://auth.openai.com/.well-known/openid-configuration
- https://github.com/panva/jose
