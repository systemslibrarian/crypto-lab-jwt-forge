# crypto-lab-jwt-forge

## What It Is

JWT Forge is a browser playground for **JWS signature verification** — the integrity layer
under JSON Web Tokens. It signs and verifies tokens with real WebCrypto primitives:
**HMAC-SHA256 (HS256)**, **RSASSA-PKCS1-v1_5 (RS256)**, **ECDSA P-256 (ES256)**, and the
unsecured **`none`** algorithm, following RFC 7515 (JWS) and RFC 7519 (JWT). The signature
proves a token's **integrity and origin** — it is *not* encryption, so the contents stay
readable by anyone. The security model is mixed: HS256 is symmetric (one shared secret),
while RS256 and ES256 are asymmetric (a private key signs, a public key verifies). The demo
exists to make two classic structural verification bugs — `alg:none` and HS/RS key
confusion — concrete, by running the same forged token against a *correct* verifier and a
deliberately *vulnerable* one.

## When to Use It

- **Stateless service-to-service auth** — a resource server can verify a JWS token's origin
  and integrity from a key alone, with no session lookup, because the signature binds the
  claims to the issuer.
- **Asymmetric signing (RS256 / ES256) when verifiers must not be able to mint tokens** —
  only the issuer holds the private key; everyone else holds the public key and can verify
  but never forge.
- **Symmetric signing (HS256) inside a single trust domain** — when the same party issues
  and verifies and can safely share a secret, HMAC is fast and simple.
- **ES256 over RS256 when size and speed matter** — P-256 signatures are far smaller and
  faster to produce than 2048-bit RSA, which helps on constrained or high-volume paths.
- **When NOT to use it:** never reach for JWS to *hide* data — it signs, it does not encrypt
  (use JWE for confidentiality). And never accept `alg:none`, or let the token's own header
  choose the verification algorithm — that is exactly the flaw this demo exploits.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-jwt-forge](https://systemslibrarian.github.io/crypto-lab-jwt-forge/)**

Decode and inspect a token, mutate its header and claims, swap its algorithm, and launch
three scripted attacks (`alg:none`, RS/HS key confusion, and a silent-tamper control). A
**verifier-policy** panel lets you set the accepted-algorithm allowlist, choose which key the
verifier holds, and flip between a **Correct** and a **Vulnerable** verifier — with a
side-by-side comparison, a step-by-step decision trace, a guided tour, and shareable scenario
links. This demo verifies **signatures only**; it does not encrypt or decrypt anything, and
all keys are generated in your browser per session and never leave the page.

## What Can Go Wrong

- Trusting the token's own `alg` header lets an attacker set `alg:none` and strip the signature entirely.
- HS/RS key confusion: a verifier that handles all algorithms in one path can be tricked into verifying an HS256 token using the RSA *public* key as the HMAC secret, letting anyone forge tokens.
- Treating a signed JWT as confidential — JWS signs but does not encrypt, so the base64url payload is readable by anyone who holds the token.
- A valid signature is not authorization — skipping expiry, audience, or issuer claim checks lets stale or misdirected tokens through.
- Weak or shared HS256 secrets can be brute-forced offline once a single token is captured.

## Real-World Usage

- Bearer tokens for stateless API and service-to-service authentication (OAuth 2.0 and OpenID Connect ID tokens).
- Session and access tokens in single-page apps and mobile clients.
- Asymmetric signing (RS256/ES256) where one identity provider mints tokens and many resource servers verify them with the public key.
- The `alg:none` and key-confusion bugs are a real, repeatedly rediscovered class of vulnerability in JWT libraries and deployments.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-jwt-forge
cd crypto-lab-jwt-forge
npm install
npm run dev
```

## Related Demos

- [crypto-lab-ecdsa-forge](https://systemslibrarian.github.io/crypto-lab-ecdsa-forge/) — the ES256 signature scheme and how nonce reuse forges it.
- [crypto-lab-rsa-forge](https://systemslibrarian.github.io/crypto-lab-rsa-forge/) — the RS256 primitive with its OAEP/PSS/PKCS#1 attacks.
- [crypto-lab-ed25519-forge](https://systemslibrarian.github.io/crypto-lab-ed25519-forge/) — a modern signature scheme and the verification subtleties that bite implementers.
- [crypto-lab-timing-oracle](https://systemslibrarian.github.io/crypto-lab-timing-oracle/) — why HMAC and signature checks must be constant-time.
- [crypto-lab-padding-oracle](https://systemslibrarian.github.io/crypto-lab-padding-oracle/) — another structural verification bug exploited a byte at a time.

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
