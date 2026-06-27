# JWT Forge

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

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-jwt-forge
cd crypto-lab-jwt-forge
npm install
npm run dev
```

No environment variables are required — everything runs client-side with no backend.

## Part of the Crypto-Lab Suite

> One of 100+ live browser demos at
> [systemslibrarian.github.io/crypto-lab](https://systemslibrarian.github.io/crypto-lab/)
> — spanning Atbash (600 BCE) through NIST FIPS 203/204/205 (2024).

---

*"Whether you eat or drink, or whatever you do, do all to the glory of God." — 1 Corinthians 10:31*
