# Suggestions to Make JWT Forge a 10/10 Demo

## Highest-impact upgrades

1. Add a guided "90-second exploit path" mode.
   - Keep the freeform playground, but add a stepper that walks users through: genuine token -> attacker edit -> vulnerable accept -> correct reject.
   - Use the existing `alg:none`, key-confusion, and silent-tamper launchers as scripted steps.
   - This would make the core lesson land even for users who do not already know JWT internals.

2. Add a visual verifier decision trace.
   - Show a compact flow for each verification: token claims alg -> app policy allowlist -> key type check -> signature routine -> claim checks -> decision.
   - Highlight the exact branch where the vulnerable verifier goes wrong.
   - The current causal text is good; a trace would make the contrast instantly inspectable.

3. Add a side-by-side "Correct vs Vulnerable" result view.
   - Instead of toggling one verifier at a time, let users run both on the same token and see two columns.
   - Include signature status, claim status, chosen alg, key material type, invariant triggered, and final decision.
   - This would reduce cognitive load and make the demo stronger in talks, docs, and screenshots.

4. Turn policy invariants into first-class teaching objects.
   - Add a small invariant checklist: "alg must be allowlisted by the app", "key type must match alg", "none is disabled unless explicitly allowed", "claims are checked after signature validity".
   - When a token is rejected, pulse the invariant that caught it.
   - This reinforces the core security principle: the verifier policy controls trust, not the attacker-controlled header.

5. Add an attacker notebook panel.
   - For each attack, show the exact forged header and payload before/after.
   - Include the signing input string `base64url(header) + '.' + base64url(payload)`.
   - For key confusion, show that the HMAC secret is literally the public RSA PEM bytes.

## Teaching polish

6. Add preset lessons with clear names.
   - "Lesson 1: Tampering without a bug fails"
   - "Lesson 2: alg:none succeeds only if the verifier trusts the header"
   - "Lesson 3: RS/HS confusion succeeds when key type is not bound to alg"
   - "Lesson 4: Defense is policy plus key binding"

7. Add a tiny glossary drawer.
   - Define JWS, JWT, header, payload, signature, `alg`, allowlist, HMAC, RSA public key, and key confusion.
   - Keep it collapsible so the main demo remains focused.

8. Add copyable "what just happened" summaries.
   - After each attack, provide a one-paragraph explanation suitable for a slide, classroom note, or bug report.
   - Example: "This token was accepted because the vulnerable verifier let the token choose HS256 and reused an RSA public key as an HMAC secret."

9. Add shareable scenario links.
   - Encode the selected attack, verifier mode, accepted algorithms, held key, and token view in the URL hash.
   - This makes it easy to send someone directly to the key-confusion aha moment.

10. Add a "reset lab" and "randomize identity" control.
    - Reset already exists for the token, but a full lab reset could restore policy, verifier mode, result, and selected view.
    - Randomizing names, subjects, and roles would make repeated demos feel less canned.

## Technical rigor

11. Expand negative cases around malformed and hostile tokens.
    - Invalid base64url segments.
    - Header or payload that decodes to arrays, null, strings, or numbers.
    - Missing `alg`, unknown `alg`, duplicate-looking fields, empty signature, extra token segments.
    - Expired `exp`, future `nbf`, and missing claim edge cases.

12. Add tests that pin the vulnerable behavior intentionally.
    - Name them as deliberate vulnerabilities so future maintainers do not "fix" the teaching contrast accidentally.
    - Example expectation: key confusion is accepted by `verifyVulnerable` and rejected by `verifyCorrect` for the same forged token.

13. Add property-style checks for base64url and token parsing.
    - Round-trip arbitrary UTF-8 strings through base64url encode/decode.
    - Assert that parse failures always reject closed instead of partially trusting decoded data.

14. Add a small compatibility matrix.
    - Rows: token alg `RS256`, `HS256`, `ES256`, `none`.
    - Columns: held key type and accepted alg policy.
    - Cells: correct verifier decision and reason.
    - This would make the type-binding defense visibly complete.

15. Consider showing real-world prevention rules.
    - "Never derive accepted algorithms from the token header."
    - "Bind each key to exactly the algorithms it may verify."
    - "Disable `none` unless the surrounding protocol explicitly requires unsecured JWS."
    - "Reject before claims are trusted."

## Product and presentation polish

16. Improve visual hierarchy for live demos.
    - Make the current token state, verifier mode, and final decision readable from the back of a room.
    - Keep the dense controls, but add a presentation-friendly result summary strip at the top.

17. Add animation only where it teaches causality.
    - Animate the transition from edited payload to signature mismatch.
    - Animate the vulnerable verifier choosing its routine from the attacker-controlled `alg`.
    - Respect the existing reduced-motion support.

18. Add keyboard-first ergonomics.
    - Shortcuts for verify, reset, run vulnerable, run correct, and launch the selected attack.
    - Keep visible focus states and expose shortcuts through tooltips or command labels.

19. Add accessible structured status output.
    - The result banner already uses live status behavior; extend that with concise screen-reader summaries for the current attack and invariant.
    - Ensure color is never the only signal for accepted, rejected, or fooled.

20. Add exportable evidence.
    - A "Copy report" button could include token header, payload diff, policy, verifier mode, result, and causal explanation.
    - This would make the playground useful for teaching, issue reports, and security review notes.

## Stretch ideas

21. Add a mini "fix the verifier" challenge.
    - Show pseudocode for the vulnerable verifier with three highlighted bugs.
    - Let users toggle fixes and watch attacks stop working.

22. Add optional library mapping.
    - Show how the safe rules map to common JWT library configuration patterns.
    - Keep this general enough to avoid becoming outdated vendor documentation.

23. Add a timeline of famous JWT verification mistakes.
    - Keep it short and educational: `alg:none`, RS/HS confusion, weak secrets, missing claim validation.
    - Separate structural verification bugs from password-strength or operational issues.

24. Add a threat-model tab.
    - Clarify attacker capabilities: can read tokens, can modify tokens, may know public keys, cannot know private keys or strong HMAC secrets.
    - This helps users understand why each demo attack is realistic.

25. Add screenshots or a short GIF to the project README.
    - Capture the vulnerable accept and correct reject states.
    - A strong README would make the demo easier to evaluate before running it.

## My recommended path to 10/10

Build these in order:

1. Side-by-side verifier results.
2. Visual decision trace.
3. Guided lesson mode.
4. Expanded negative tests.
5. Shareable scenario links.

Those five changes would make the demo clearer, more memorable, easier to present, and harder to regress while preserving the focused scope that already works well.