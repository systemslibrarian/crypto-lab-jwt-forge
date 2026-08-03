import { expect, test, type Locator, type Page } from '@playwright/test';

/**
 * Functional gate: the verdicts, traces and counters this lab exists to teach.
 *
 * The a11y spec proves the page is reachable; this spec proves it is TRUE. Every
 * headline here is checked against something the page itself computed — the token
 * bytes it rendered, the numbers it printed — rather than against a string this
 * file happens to know. Both attacks and the control are driven end to end, in
 * both verifiers, so "the vulnerable one accepts, the correct one refuses, and it
 * says why" is asserted rather than assumed.
 */

// ---- helpers -------------------------------------------------------------------

function b64urlDecode(seg: string): string {
  return Buffer.from(seg.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}

function decodeToken(token: string): { header: Record<string, unknown>; claims: Record<string, unknown>; sig: string } {
  const [h, p, s] = token.split('.');
  return {
    header: JSON.parse(b64urlDecode(h)) as Record<string, unknown>,
    claims: JSON.parse(b64urlDecode(p)) as Record<string, unknown>,
    sig: s ?? '',
  };
}

/** Load the app and wait for the async key generation + first verification. */
async function boot(page: Page): Promise<void> {
  await page.goto('.');
  await page.locator('#token-panel .tabs').waitFor();
  await page.locator('#result-panel .banner').first().waitFor();
}

/** The compact JWS the page is currently showing, read out of its own raw view. */
async function currentToken(page: Page): Promise<string> {
  await page.locator('.tab[data-view="raw"]').click();
  const text = await page.locator('.raw-token').innerText();
  return text.replace(/\s+/g, '');
}

async function openDecoded(page: Page): Promise<void> {
  await page.locator('.tab[data-view="decoded"]').click();
  await page.locator('#ta-header').waitFor();
}

/** Value cell of a status row, selected by its exact label. */
function statusRow(scope: Locator, label: string): Locator {
  return scope.locator(`.status-row:has(> .k:text-is(${JSON.stringify(label)}))`);
}

async function statusValue(scope: Locator, label: string): Promise<string> {
  const row = statusRow(scope, label);
  await expect(row).toHaveCount(1);
  const full = (await row.innerText()).trim();
  return full.slice(label.length).trim();
}

/**
 * Trace steps must partition into exactly the four statuses, and at most one step
 * may claim to be the one that decided the outcome.
 */
async function traceStats(scope: Locator): Promise<{
  total: number;
  pass: number;
  fail: number;
  skip: number;
  info: number;
  decisive: number;
}> {
  const steps = scope.locator('.trace-step');
  const total = await steps.count();
  const pass = await scope.locator('.trace-step.pass').count();
  const fail = await scope.locator('.trace-step.fail').count();
  const skip = await scope.locator('.trace-step.skip').count();
  const info = await scope.locator('.trace-step.info').count();
  const decisive = await scope.locator('.trace-step.decisive').count();
  expect(pass + fail + skip + info, 'every trace step carries exactly one status class').toBe(total);
  expect(total, 'a decision trace is never empty').toBeGreaterThan(0);
  expect(decisive, 'at most one step may be marked "decided here"').toBeLessThanOrEqual(1);
  return { total, pass, fail, skip, info, decisive };
}

const result = (page: Page): Locator => page.locator('#result-panel');
const headline = (scope: Locator): Locator => scope.locator('.headline').first();

// ---- 1. the genuine token ------------------------------------------------------

test('genuine RS256 token: the headline matches the token the page actually rendered', async ({ page }) => {
  await boot(page);

  const token = await currentToken(page);
  const { header, claims, sig } = decodeToken(token);

  // The page's verdict is checked against the token IT produced, not a literal.
  expect(header.alg).toBe('RS256');
  expect(sig).not.toBe('');
  expect(await statusValue(result(page), 'Token claimed alg')).toBe(String(header.alg));
  expect(await statusValue(result(page), 'Verifier mode')).toContain('Correct');

  await expect(headline(result(page))).toHaveText(/Valid signature — all checks passed/);
  await expect(result(page).locator('.banner').first()).toHaveClass(/valid/);
  expect(await statusValue(result(page), 'Signature check')).toContain('valid');
  expect(await statusValue(result(page), 'Claim check (exp/nbf)')).toContain('valid');
  await expect(result(page).locator('.reason').first()).toHaveText(
    new RegExp(`valid ${header.alg} signature`),
  );

  // A clean accept means every trace step passed and nothing "decided" against it.
  const t = await traceStats(result(page));
  expect(t.fail).toBe(0);
  expect(t.pass).toBe(t.total);
  expect(t.decisive).toBe(0);

  // The claims are the ones the token carries, and it is genuinely not escalated.
  expect(claims.admin).toBe(false);
  expect(typeof claims.exp).toBe('number');
});

// ---- 2. attack: alg:none -------------------------------------------------------

test('alg:none SUCCEEDS against the vulnerable verifier, and the page says why', async ({ page }) => {
  await boot(page);
  await page.locator('[data-action="attack-none"]').click();
  await expect(headline(result(page))).toHaveText(/FORGED TOKEN ACCEPTED/);

  // The forged token really is unsecured and really is escalated.
  const token = await currentToken(page);
  const { header, claims, sig } = decodeToken(token);
  expect(header.alg).toBe('none');
  expect(sig, 'an alg:none token ends in a bare trailing dot').toBe('');
  expect(claims.admin, 'the attack escalated the claim it says it escalated').toBe(true);
  expect(claims.role).toBe('admin');

  await expect(result(page).locator('.banner').first()).toHaveClass(/forged/);
  expect(await statusValue(result(page), 'Token claimed alg')).toBe(String(header.alg));
  expect(await statusValue(result(page), 'Verifier mode')).toContain('Vulnerable');
  // The signature was never checked — the page must not claim otherwise.
  expect(await statusValue(result(page), 'Signature check')).toContain('not-checked');
  await expect(result(page).locator('.reason').first()).toHaveText(
    /skipped signature checking entirely and accepted it/,
  );

  // The causal chain explains the mechanism.
  const causal = result(page).locator('.causal');
  await expect(causal.locator('h3')).toHaveText(/alg:none — causal chain/);
  await expect(causal.locator('.chain')).toHaveText(/no signature is verified/);
  await expect(causal).toContainText('requires "none" to be on an explicit allowlist');

  const t = await traceStats(result(page));
  expect(t.decisive).toBe(1);
  await expect(result(page).locator('.trace-step.decisive')).toContainText(
    'alg:none → skip signature check',
  );
});

test('alg:none is REFUSED by the correct verifier, naming the invariant that caught it', async ({ page }) => {
  await boot(page);
  await page.locator('[data-action="attack-none"]').click();
  await expect(headline(result(page))).toHaveText(/FORGED TOKEN ACCEPTED/);

  const forged = await currentToken(page);
  await page.locator('[data-action="contrast"]').click();
  await expect(headline(result(page))).toHaveText(/REJECTED AS EXPECTED/);

  // Same token bytes — only the verifier changed.
  expect(await currentToken(page)).toBe(forged);
  expect(await statusValue(result(page), 'Verifier mode')).toContain('Correct');
  expect(await statusValue(result(page), 'Invariant that caught it')).toBe(
    'alg not in allowlist (invariant #1)',
  );
  await expect(result(page).locator('.reason').first()).toHaveText(
    /alg "none" is not in the verifier's accepted-algorithms allowlist/,
  );
  expect(await statusValue(result(page), 'Signature check')).toContain('not-checked');

  const t = await traceStats(result(page));
  expect(t.decisive).toBe(1);
  await expect(result(page).locator('.trace-step.decisive')).toContainText('Claimed alg in allowlist?');
});

test('an explicitly allowlisted alg:none token is never reported as a valid signature', async ({ page }) => {
  await boot(page);
  await page.locator('[data-action="attack-none"]').click();
  await expect(headline(result(page))).toHaveText(/FORGED TOKEN ACCEPTED/);
  await page.locator('[data-action="contrast"]').click();
  await expect(headline(result(page))).toHaveText(/REJECTED AS EXPECTED/);

  // The application opts in to `none`. It is now accepted — but as UNSECURED.
  await page.locator('input[data-action="alg"][data-alg="none"]').click();
  await expect(headline(result(page))).toHaveText(/ACCEPTED UNSECURED — NO SIGNATURE WAS CHECKED/);
  await expect(headline(result(page))).not.toHaveText(/Valid signature/);
  expect(await statusValue(result(page), 'Signature check')).toContain('not-checked');
  await expect(result(page).locator('.banner').first()).toHaveClass(/forged/);
  await expect(result(page).locator('.reason').first()).toHaveText(/NO signature was checked/);
});

// ---- 3. attack: RS/HS key confusion --------------------------------------------

test('key confusion SUCCEEDS against the vulnerable verifier using the public key as the secret', async ({ page }) => {
  test.setTimeout(60_000);
  await boot(page);
  await page.locator('[data-action="attack-confusion"]').click();
  await expect(headline(result(page))).toHaveText(/FORGED TOKEN ACCEPTED/);

  const token = await currentToken(page);
  const { header, claims, sig } = decodeToken(token);
  expect(header.alg, 'the forgery re-signed the token as HS256').toBe('HS256');
  expect(sig, 'unlike alg:none, this forgery carries a real MAC').not.toBe('');
  expect(claims.admin).toBe(true);

  expect(await statusValue(result(page), 'Token claimed alg')).toBe(String(header.alg));
  expect(await statusValue(result(page), 'Signature check')).toContain('valid');
  await expect(result(page).locator('.reason').first()).toHaveText(
    /a public value was used as a secret/,
  );

  const causal = result(page).locator('.causal');
  await expect(causal.locator('h3')).toHaveText(/RS\/HS key confusion — causal chain/);
  await expect(causal).toContainText('BEGIN PUBLIC KEY');
  await expect(causal).toContainText('type-incompatible with the HMAC path');

  const t = await traceStats(result(page));
  expect(t.decisive).toBe(1);
  await expect(result(page).locator('.trace-step.decisive')).toContainText('RS/HS confusion');
});

test('key confusion is REFUSED by the correct verifier, and both verdicts show side by side', async ({ page }) => {
  test.setTimeout(60_000);
  await boot(page);
  await page.locator('[data-action="attack-confusion"]').click();
  await expect(headline(result(page))).toHaveText(/FORGED TOKEN ACCEPTED/);
  const forged = await currentToken(page);

  await page.locator('[data-action="contrast"]').click();
  await expect(headline(result(page))).toHaveText(/REJECTED AS EXPECTED/);
  expect(await currentToken(page)).toBe(forged);
  expect(await statusValue(result(page), 'Invariant that caught it')).toBe(
    'alg not in allowlist (invariant #1)',
  );

  // Side by side: one token, two implementations, opposite outcomes.
  await page.locator('[data-action="compare-on"]').click();
  await page.locator('.compare-grid').waitFor();
  expect(await currentToken(page)).toBe(forged);

  const cols = result(page).locator('.result-col');
  await expect(cols).toHaveCount(2);
  const correct = cols.nth(0);
  const vulnerable = cols.nth(1);
  await expect(correct.locator('.col-title')).toHaveText(/Correct verifier/);
  await expect(vulnerable.locator('.col-title')).toHaveText(/Vulnerable verifier/);

  await expect(headline(correct)).toHaveText(/REJECTED AS EXPECTED/);
  await expect(headline(vulnerable)).toHaveText(/FORGED TOKEN ACCEPTED/);
  expect(await statusValue(correct, 'Signature')).toContain('not-checked');
  expect(await statusValue(vulnerable, 'Signature')).toContain('valid');
  // Both columns judged the SAME token, so both must report the same claimed alg.
  const claimedCorrect = await statusValue(correct, 'Claimed alg');
  expect(claimedCorrect).toBe(await statusValue(vulnerable, 'Claimed alg'));
  expect(claimedCorrect).toBe(String(decodeToken(forged).header.alg));

  // The screen-reader summary must agree with the two banners.
  await expect(result(page).locator('.sr-only[role="status"]')).toHaveText(
    'Correct verifier rejects; Vulnerable verifier accepts and is fooled.',
  );

  await traceStats(correct);
  await traceStats(vulnerable);
});

test('key confusion fails when the verifier does not hold the key the attacker MACed with', async ({ page }) => {
  test.setTimeout(60_000);
  await boot(page);
  await page.locator('[data-action="attack-confusion"]').click();
  await expect(headline(result(page))).toHaveText(/FORGED TOKEN ACCEPTED/);

  // The forgery's "secret" is the RSA public key. Hand the verifier a different key
  // and the same broken code path rejects it — the attack is key-specific, not magic.
  await page.locator('input[data-action="heldkey"][data-key="ecPublic"]').click();
  await expect(headline(result(page))).toHaveText(/Rejected|REJECTED AS EXPECTED/);
  expect(await statusValue(result(page), 'Signature check')).toContain('invalid');
  await expect(result(page).locator('.reason').first()).toHaveText(/signature did not verify/);

  await page.locator('input[data-action="heldkey"][data-key="hmac"]').click();
  await expect(result(page).locator('.reason').first()).toHaveText(
    /HMAC with the genuine shared secret/,
  );
  expect(await statusValue(result(page), 'Signature check')).toContain('invalid');
});

// ---- 4. control: silent tamper -------------------------------------------------

test('silent tamper is refused by BOTH verifiers — the control that proves the point', async ({ page }) => {
  test.setTimeout(60_000);
  await boot(page);
  const genuine = await currentToken(page);
  await page.locator('[data-action="attack-tamper"]').click();
  await expect(headline(result(page))).toHaveText(/REJECTED AS EXPECTED/);

  const token = await currentToken(page);
  const before = decodeToken(genuine);
  const after = decodeToken(token);
  expect(after.claims.admin, 'the payload really was edited').toBe(true);
  expect(after.sig, 'the signature really was left untouched').toBe(before.sig);

  // Vulnerable verifier first — its broken paths still catch a plain forgery.
  expect(await statusValue(result(page), 'Verifier mode')).toContain('Vulnerable');
  expect(await statusValue(result(page), 'Signature check')).toContain('invalid');
  expect(await statusValue(result(page), 'Claim check (exp/nbf)')).toContain('not-checked');
  await expect(result(page).locator('.causal .chain')).toHaveText(/It does NOT pass/);

  await page.locator('[data-action="contrast"]').click();
  await expect(result(page).locator('.reason').first()).toHaveText(
    /signature does not verify under the held RsaPublicKey/,
  );
  await expect(headline(result(page))).toHaveText(/REJECTED AS EXPECTED/);
  expect(await statusValue(result(page), 'Verifier mode')).toContain('Correct');
  expect(await statusValue(result(page), 'Signature check')).toContain('invalid');

  // And side by side, so "rejected everywhere" is visible in one shot.
  await page.locator('[data-action="compare-on"]').click();
  await page.locator('.compare-grid').waitFor();
  const cols = result(page).locator('.result-col');
  await expect(headline(cols.nth(0))).toHaveText(/REJECTED AS EXPECTED/);
  await expect(headline(cols.nth(1))).toHaveText(/REJECTED AS EXPECTED/);
  expect(await statusValue(cols.nth(0), 'Signature')).toContain('invalid');
  expect(await statusValue(cols.nth(1), 'Signature')).toContain('invalid');
  await expect(result(page).locator('.sr-only[role="status"]')).toHaveText(
    'Correct verifier rejects; Vulnerable verifier rejects.',
  );
});

test('hand-edited claims with the old signature are rejected, and the edit is visible in the diff', async ({ page }) => {
  await boot(page);
  const genuine = await currentToken(page);
  await openDecoded(page);

  const claims = JSON.parse(await page.locator('#ta-payload').inputValue()) as Record<string, unknown>;
  expect(claims.admin).toBe(false);
  claims.admin = true;
  await page.locator('#ta-payload').fill(JSON.stringify(claims, null, 2));
  await page.locator('[data-action="tamper"]').click();

  await expect(headline(result(page))).toHaveText(/REJECTED AS EXPECTED/);
  expect(await statusValue(result(page), 'Signature check')).toContain('invalid');
  await expect(result(page).locator('.causal h3')).toHaveText(/manual tamper — causal chain/);

  const token = await currentToken(page);
  expect(decodeToken(token).sig).toBe(decodeToken(genuine).sig);
  expect(decodeToken(token).claims.admin).toBe(true);
});

// ---- 5. the diff table is a real diff ------------------------------------------

test('the diff table lists exactly the fields that actually differ', async ({ page }) => {
  await boot(page);
  const genuine = await currentToken(page);
  await page.locator('[data-action="attack-none"]').click();
  await expect(headline(result(page))).toHaveText(/FORGED TOKEN ACCEPTED/);
  const forged = await currentToken(page);

  await page.locator('.tab[data-view="diff"]').click();
  await page.locator('.diff-table').waitFor();

  const rows = page.locator('.diff-row');
  const total = await rows.count();
  const added = await page.locator('.diff-row.added').count();
  const removed = await page.locator('.diff-row.removed').count();
  const changed = await page.locator('.diff-row.changed').count();
  expect(added + removed + changed, 'every diff row is classified exactly once').toBe(total);

  // Recompute the expected diff from the two tokens the page itself rendered.
  const a = decodeToken(genuine);
  const b = decodeToken(forged);
  const expected = new Set<string>();
  const collect = (section: string, x: Record<string, unknown>, y: Record<string, unknown>): void => {
    for (const k of new Set([...Object.keys(x), ...Object.keys(y)])) {
      if (k in x && k in y && JSON.stringify(x[k]) === JSON.stringify(y[k])) continue;
      expected.add(`${section}.${k}`);
    }
  };
  collect('header', a.header, b.header);
  collect('claims', a.claims, b.claims);
  if (a.sig !== b.sig) expected.add('signature');

  const listed = new Set(
    await rows.evaluateAll((els) => els.map((el) => (el.firstElementChild as HTMLElement).innerText.trim())),
  );
  expect([...listed].sort()).toEqual([...expected].sort());
  expect(total).toBe(expected.size);

  // Specifically: alg was swapped and admin was escalated.
  expect(listed.has('header.alg')).toBe(true);
  expect(listed.has('claims.admin')).toBe(true);
  await expect(page.locator('.diff-row', { hasText: 'header.alg' })).toContainText('"none"');
});

// ---- 6. the verifier policy is what decides ------------------------------------

test('an empty allowlist accepts nothing — and the vulnerable verifier bypasses it under a different headline', async ({ page }) => {
  await boot(page);
  await expect(headline(result(page))).toHaveText(/Valid signature — all checks passed/);

  // Remove the only allowlisted alg. The correct verifier now accepts nothing at all.
  await page.locator('input[data-action="alg"][data-alg="RS256"]').click();
  await expect(result(page).locator('.reason').first()).toHaveText(
    /policy accepts no algorithms — an empty\/missing allowlist means accept NOTHING/,
  );
  await expect(headline(result(page))).toHaveText(/^✓ Rejected$/);
  expect(await statusValue(result(page), 'Invariant that caught it')).toBe(
    'required allowlist (invariant #1)',
  );
  expect(await statusValue(result(page), 'Token claimed alg')).toBe('—');
  const t = await traceStats(result(page));
  expect(t.total, 'an empty allowlist stops before the token is even parsed').toBe(1);
  expect(t.decisive).toBe(1);

  // The vulnerable verifier ignores the allowlist. That is a policy bypass, not a
  // forged signature, and the page must not conflate the two.
  await page.locator('[data-action="mode"][data-mode="vulnerable"]').click();
  await expect(headline(result(page))).toHaveText(/ACCEPTED OUTSIDE THE POLICY ALLOWLIST/);
  await expect(headline(result(page))).not.toHaveText(/FORGED TOKEN ACCEPTED/);
  expect(await statusValue(result(page), 'Signature check')).toContain('valid');
  await expect(result(page).locator('.reason').first()).toHaveText(
    /is NOT in the application's allowlist — this verifier never checked/,
  );
  await expect(result(page).locator('.trace-step.decisive')).toContainText(
    'Alg was on the application allowlist?',
  );
});

test('the correct verifier refuses to improvise when it holds no key for the token alg', async ({ page }) => {
  await boot(page);
  // Genuine RS256 token, but hand the verifier an EC public key instead.
  await page.locator('input[data-action="heldkey"][data-key="ecPublic"]').click();
  await expect(result(page).locator('.reason').first()).toHaveText(
    /the verifier holds no key for alg "RS256"/,
  );
  expect(await statusValue(result(page), 'Invariant that caught it')).toBe(
    'no held key for alg (type binding, invariant #3)',
  );
  expect(await statusValue(result(page), 'Signature check')).toContain('not-checked');
  await expect(result(page).locator('.trace-step.decisive')).toContainText(
    'Verifier holds a key bound to this alg?',
  );
});

// ---- 7. genuinely re-signing under each algorithm ------------------------------

for (const [alg, keyId, keyKind] of [
  ['HS256', 'hmac', 'HmacKey'],
  ['ES256', 'ecPublic', 'EcPublicKey'],
] as const) {
  test(`re-signing as ${alg} verifies cleanly once the policy allows ${alg} and holds the ${keyKind}`, async ({ page }) => {
    test.setTimeout(60_000);
    await boot(page);
    await openDecoded(page);
    await page.locator('#ta-header').fill(JSON.stringify({ alg, typ: 'JWT' }, null, 2));
    await page.locator('[data-action="resign"]').click();

    // Same key policy as before: the token now names an alg the app never allowed.
    await expect(result(page).locator('.reason').first()).toHaveText(
      new RegExp(`alg "${alg}" is not in the verifier's accepted-algorithms allowlist`),
    );

    await page.locator(`input[data-action="heldkey"][data-key="${keyId}"]`).click();
    await page.locator(`input[data-action="alg"][data-alg="${alg}"]`).click();
    await expect(headline(result(page))).toHaveText(/Valid signature — all checks passed/);

    const token = await currentToken(page);
    expect(decodeToken(token).header.alg).toBe(alg);
    expect(await statusValue(result(page), 'Token claimed alg')).toBe(alg);
    expect(await statusValue(result(page), 'Signature check')).toContain('valid');
    await expect(result(page).locator('.trace-step', { hasText: 'Routine chosen by KEY TYPE' })).toContainText(
      `using ${keyKind} → ${alg} routine`,
    );
    const t = await traceStats(result(page));
    expect(t.fail).toBe(0);
    expect(t.decisive).toBe(0);
  });
}

test('an expired token reports a VALID signature and INVALID claims, with numbers that agree', async ({ page }) => {
  await boot(page);
  await openDecoded(page);
  const claims = JSON.parse(await page.locator('#ta-payload').inputValue()) as Record<string, unknown>;
  const pastExp = 1_000_000;
  claims.exp = pastExp;
  await page.locator('#ta-payload').fill(JSON.stringify(claims, null, 2));
  await page.locator('[data-action="resign"]').click();

  await expect(result(page).locator('.reason').first()).toHaveText(/signature is valid but token expired/);
  // Signature and claim validity are reported separately, never collapsed.
  expect(await statusValue(result(page), 'Signature check')).toContain('valid');
  expect(await statusValue(result(page), 'Claim check (exp/nbf)')).toContain('invalid');

  const detail = await statusValue(result(page), 'Claim detail');
  const m = detail.match(/exp=(\d+) < now=(\d+)/);
  expect(m, `claim detail should print both clocks, got: ${detail}`).not.toBeNull();
  const [, expStr, nowStr] = m!;
  expect(Number(expStr), 'the exp echoed back is the one we signed').toBe(pastExp);
  expect(Number(nowStr), 'the verifier clock really is past that exp').toBeGreaterThan(pastExp);
  // ...and the token on screen carries that exact exp.
  expect(decodeToken(await currentToken(page)).claims.exp).toBe(pastExp);

  await expect(result(page).locator('.trace-step.decisive')).toContainText('Claims (exp/nbf) valid?');
});

// ---- 8. fail-closed input handling ---------------------------------------------

test('the token editor fails closed on bad JSON and on an unsignable alg', async ({ page }) => {
  await boot(page);
  await openDecoded(page);
  const before = await currentToken(page);
  await openDecoded(page);

  await page.locator('#ta-header').fill('{ not json');
  await page.locator('[data-action="resign"]').click();
  await expect(page.locator('#token-panel .form-error')).toHaveText(/Header or payload is not valid JSON/);
  expect(await currentToken(page), 'a rejected edit must not replace the token').toBe(before);

  await openDecoded(page);
  await page.locator('#ta-header').fill(JSON.stringify({ alg: 'none' }));
  await page.locator('[data-action="resign"]').click();
  await expect(page.locator('#token-panel .form-error')).toHaveText(
    /alg:none has no signing key — use an attack launcher/,
  );
  expect(await currentToken(page)).toBe(before);
});

test('a malformed pasted token is rejected at parse time, before any verification', async ({ page }) => {
  await boot(page);
  await page.locator('.tab[data-view="raw"]').click();
  await page.locator('[data-action="paste-toggle"]').click();
  await page.locator('#paste-input').fill('not-a-token');
  await page.locator('[data-action="paste-apply"]').click();

  await expect(result(page).locator('.reason').first()).toHaveText(
    /expected 3 segments separated by '\.', found 1/,
  );
  expect(await statusValue(result(page), 'Invariant that caught it')).toBe(
    'structure: a compact JWS is header.payload.signature',
  );
  expect(await statusValue(result(page), 'Signature check')).toContain('not-checked');
  expect(await statusValue(result(page), 'Claim check (exp/nbf)')).toContain('not-checked');

  // The decoded view says so too, rather than rendering half a token.
  await page.locator('.tab[data-view="decoded"]').click();
  await expect(page.locator('#token-panel')).toContainText('This token cannot be decoded');
});

// ---- 9. the guided tour, and its own counter -----------------------------------

test('the guided tour walks all 7 steps, and each step lands on the verdict it promises', async ({ page }) => {
  test.setTimeout(90_000);
  await boot(page);

  // The blurb's step count must match the tour the code actually contains.
  const blurb = await page.locator('#tour h2').innerText();
  const promised = Number(blurb.match(/(\d+) steps/)![1]);

  await page.locator('[data-action="tour-start"]').click();
  await expect(page.locator('#tour h2')).toHaveText(/step 1 of \d+/);
  const total = Number((await page.locator('#tour h2').innerText()).match(/of (\d+)/)![1]);
  expect(total, 'the advertised step count is the real one').toBe(promised);
  expect(await page.locator('#tour .tour-progress .dot').count()).toBe(total);

  const expected: RegExp[] = [
    /Valid signature — all checks passed/,
    /REJECTED AS EXPECTED/, // silent tamper vs the vulnerable verifier
    /FORGED TOKEN ACCEPTED/, // alg:none vs the vulnerable verifier
    /REJECTED AS EXPECTED/, // alg:none vs the correct verifier
    /FORGED TOKEN ACCEPTED/, // key confusion vs the vulnerable verifier
    /REJECTED AS EXPECTED/, // key confusion vs the correct verifier
  ];
  expect(total).toBe(expected.length + 1); // + the closing side-by-side step

  for (let i = 1; i <= total; i++) {
    await expect(page.locator('#tour h2')).toHaveText(new RegExp(`step ${i} of ${total}`));
    // Progress dots: exactly one current, exactly i-1 done, none double-counted.
    const dots = page.locator('#tour .tour-progress .dot');
    expect(await dots.count()).toBe(total);
    expect(await page.locator('#tour .tour-progress .dot.on').count()).toBe(1);
    expect(await page.locator('#tour .tour-progress .dot.done').count()).toBe(i - 1);
    const prev = page.locator('[data-action="tour-prev"]');
    if (i === 1) await expect(prev, 'step 1 has nothing to go back to').toBeDisabled();
    else await expect(prev).toBeEnabled();

    if (i <= expected.length) {
      await expect(headline(result(page))).toHaveText(expected[i - 1]);
      await traceStats(result(page));
    } else {
      // Final step: both verifiers on the same forged token, side by side.
      await page.locator('.compare-grid').waitFor();
      const cols = result(page).locator('.result-col');
      await expect(cols).toHaveCount(2);
      await expect(headline(cols.nth(0))).toHaveText(/REJECTED AS EXPECTED/);
      await expect(headline(cols.nth(1))).toHaveText(/FORGED TOKEN ACCEPTED/);
    }

    if (i < total) await page.locator('[data-action="tour-next"]').click();
  }

  await expect(page.locator('[data-action="tour-next"]')).toHaveText(/Finish/);
  await page.locator('[data-action="tour-next"]').click();
  await expect(page.locator('[data-action="tour-start"]')).toBeVisible();
});

// ---- 10. README promises a user can see ----------------------------------------

test('the vulnerable verifier is labelled as broken wherever it is selected', async ({ page }) => {
  await boot(page);
  await expect(page.locator('.vuln-warning')).not.toHaveClass(/\bon\b/);
  await expect(page.locator('#policy-panel .hint').first()).toContainText(
    'never reads the token\'s alg to choose a routine',
  );

  await page.locator('[data-action="mode"][data-mode="vulnerable"]').click();
  await expect(page.locator('.vuln-warning')).toHaveClass(/\bon\b/);
  await expect(page.locator('.vuln-warning')).toContainText('DELIBERATELY BROKEN');
  await expect(page.locator('#policy-panel .hint').first()).toContainText(
    'ignores the policy below',
  );
  expect(await statusValue(result(page), 'Verifier mode')).toContain('Vulnerable');
});

test('three scripted attacks are offered, and each one changes the token', async ({ page }) => {
  test.setTimeout(60_000);
  await boot(page);
  await expect(page.locator('#attacks .launcher-card')).toHaveCount(3);
  const genuine = await currentToken(page);

  const seen = new Set<string>([genuine]);
  for (const action of ['attack-none', 'attack-confusion', 'attack-tamper']) {
    await page.locator(`[data-action="${action}"]`).click();
    await expect(result(page).locator('.causal')).toBeVisible();
    const token = await currentToken(page);
    expect(token, `${action} must produce a token of its own`).not.toBe(genuine);
    seen.add(token);
    await page.locator('[data-action="reset"]').click();
    await expect(headline(result(page))).toHaveText(/Valid signature — all checks passed/);
    expect(await currentToken(page), 'reset restores the genuine token').toBe(genuine);
  }
  expect(seen.size, 'the three attacks are three distinct forgeries').toBe(4);
});

test('a shared scenario link reproduces the attack in a session with different keys', async ({ page, context }) => {
  test.setTimeout(90_000);
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await boot(page);
  await page.locator('[data-action="attack-confusion"]').click();
  await expect(headline(result(page))).toHaveText(/FORGED TOKEN ACCEPTED/);
  const forgedHere = await currentToken(page);

  await page.locator('[data-action="compare-on"]').click();
  await page.locator('.compare-grid').waitFor();
  await page.locator('[data-action="share"]').click();
  const link = await page.evaluate(() => navigator.clipboard.readText());
  expect(link).toContain('#s=');
  expect(page.url()).toBe(link);

  const recipient = await context.newPage();
  await recipient.goto(link);
  await recipient.locator('.compare-grid').waitFor();
  const cols = recipient.locator('#result-panel .result-col');
  await expect(cols).toHaveCount(2);
  await expect(headline(cols.nth(0))).toHaveText(/REJECTED AS EXPECTED/);
  await expect(headline(cols.nth(1))).toHaveText(/FORGED TOKEN ACCEPTED/);

  // Keys are per-session, so the bytes differ — the scenario, not the token, travels.
  const forgedThere = await currentToken(recipient);
  expect(forgedThere).not.toBe(forgedHere);
  expect(decodeToken(forgedThere).header.alg).toBe('HS256');
  expect(decodeToken(forgedThere).claims.admin).toBe(true);
  await recipient.close();
});

test('the copied summary says the same thing the result panel says', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await boot(page);
  await page.locator('[data-action="attack-none"]').click();
  await expect(headline(result(page))).toHaveText(/FORGED TOKEN ACCEPTED/);

  const reason = (await result(page).locator('.reason').first().innerText()).trim();
  const alg = await statusValue(result(page), 'Token claimed alg');
  await page.locator('[data-action="copy-summary"]').click();
  const summary = await page.evaluate(() => navigator.clipboard.readText());

  expect(summary).toContain('JWT Forge — what just happened');
  expect(summary).toContain('Scenario: alg:none');
  expect(summary).toContain(`Token claimed alg: ${alg}`);
  expect(summary).toContain('Verifier: vulnerable');
  expect(summary).toContain('Decision: ACCEPT (FOOLED)');
  expect(summary).toContain('Signature: not-checked');
  expect(summary).toContain(`Reason: ${reason}`);
});

test('nothing leaves the page: no third-party requests, no persisted key material', async ({ page }) => {
  test.setTimeout(60_000);
  const offSite: string[] = [];
  page.on('request', (r) => {
    const u = r.url();
    if (!u.startsWith('http://localhost:4655/') && !u.startsWith('data:') && !u.startsWith('blob:')) {
      offSite.push(u);
    }
  });

  await boot(page);
  await page.locator('[data-action="attack-confusion"]').click();
  await expect(headline(result(page))).toHaveText(/FORGED TOKEN ACCEPTED/);
  await page.locator('[data-action="attack-none"]').click();
  await expect(headline(result(page))).toHaveText(/FORGED TOKEN ACCEPTED/);

  expect(offSite, 'keys and tokens never leave the browser').toEqual([]);
  const persisted = await page.evaluate(() => ({
    local: Object.keys(localStorage),
    session: Object.keys(sessionStorage),
  }));
  expect(persisted.local.filter((k) => k !== 'theme'), 'only the theme preference is stored').toEqual([]);
  expect(persisted.session).toEqual([]);
  await expect(page.locator('#token-panel .notwhat')).toContainText('never persisted');
  await expect(page.locator('#token-panel .notwhat')).toContainText('Not a JWE');
});
