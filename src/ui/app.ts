import { generateSessionKeys, type SessionKeys } from '../jwt/keys.ts';
import { sign } from '../jwt/sign.ts';
import { verifyCorrect } from '../jwt/verifyCorrect.ts';
import { verifyVulnerable } from '../jwt/verifyVulnerable.ts';
import type { AlgName, VerifierPolicy, VerifyResult, VerifierKey, JwtHeader, JwtClaims, SigningKey, TraceStep } from '../jwt/types.ts';
import { isAlgName } from '../jwt/types.ts';
import { base64urlDecodeToString, base64urlEncodeString } from '../jwt/base64url.ts';
import { attackAlgNone } from '../attacks/algNone.ts';
import { attackKeyConfusion } from '../attacks/keyConfusion.ts';
import { attackSilentTamper } from '../attacks/silentTamper.ts';
import type { AttackExplanation } from '../attacks/types.ts';

type HeldKeyId = 'rsaPublic' | 'hmac' | 'ecPublic';
type TokenView = 'raw' | 'decoded' | 'diff';
type ScenarioCode = 'genuine' | 'none' | 'confusion' | 'tamper' | 'token';

interface State {
  keys: SessionKeys;
  baseToken: string;
  currentToken: string;
  view: TokenView;
  acceptedAlgs: Set<AlgName>;
  heldKey: HeldKeyId;
  mode: 'correct' | 'vulnerable';
  result?: VerifyResult;
  explanation?: AttackExplanation;
  flashPolicy: boolean;
  /** Inline error message for the token panel (replaces blocking alert()). */
  tokenError?: string;
  /** In-progress edits to the decoded JSON, preserved across tab switches. */
  draftHeader?: string;
  draftPayload?: string;
  /** Side-by-side comparison: run both verifiers on the same token. */
  compare: boolean;
  compareResults?: { correct: VerifyResult; vulnerable: VerifyResult };
  /** Guided lesson tour; undefined when not active. */
  tourIndex?: number;
  /** Which scenario produced the current token (for shareable links). */
  scenario: ScenarioCode;
}

let state: State;
let root: HTMLElement;

function prefersReducedMotion(): boolean {
  return typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;
}

/** Forget any in-progress edits/errors when the token is replaced wholesale. */
function clearDrafts(): void {
  state.draftHeader = undefined;
  state.draftPayload = undefined;
  state.tokenError = undefined;
}

function heldKeyWrapper(): VerifierKey {
  switch (state.heldKey) {
    case 'rsaPublic': return state.keys.rsaPublic;
    case 'hmac': return state.keys.hmac;
    case 'ecPublic': return state.keys.ecPublic;
  }
}

function buildPolicy(): VerifierPolicy {
  return {
    acceptedAlgs: state.acceptedAlgs,
    keys: [heldKeyWrapper()],
    nowSeconds: Math.floor(Date.now() / 1000),
  };
}

function decodeUnsafe(token: string): { header: JwtHeader; claims: JwtClaims; sig: string } | null {
  try {
    const [h, p, s] = token.split('.');
    return {
      header: JSON.parse(base64urlDecodeToString(h)) as JwtHeader,
      claims: JSON.parse(base64urlDecodeToString(p)) as JwtClaims,
      sig: s ?? '',
    };
  } catch {
    return null;
  }
}

// ---- Shareable scenario links --------------------------------------------------
//
// Keys are per-session, so we cannot share token *bytes* and expect them to verify in
// someone else's session. Instead we share a scenario DESCRIPTOR (attack + mode +
// policy + view) and re-derive the token against the recipient's freshly generated
// base token — so the alg:none / confusion "aha" reproduces faithfully. Custom tokens
// (manual edits / paste) fall back to embedding the literal token string.

interface ScenarioPayload {
  s: ScenarioCode;
  m: 'c' | 'v';
  a: string[];
  k: string;
  cmp: 0 | 1;
  v: string;
  t?: string;
}

function buildShareUrl(): string {
  const payload: ScenarioPayload = {
    s: state.scenario,
    m: state.mode === 'correct' ? 'c' : 'v',
    a: [...state.acceptedAlgs],
    k: state.heldKey,
    cmp: state.compare ? 1 : 0,
    v: state.view,
  };
  if (state.scenario === 'token') payload.t = state.currentToken;
  const code = base64urlEncodeString(JSON.stringify(payload));
  const base = location.href.split('#')[0];
  return `${base}#s=${code}`;
}

function readScenarioHash(): ScenarioPayload | null {
  const m = location.hash.match(/^#s=(.+)$/);
  if (!m) return null;
  try {
    const obj = JSON.parse(base64urlDecodeToString(m[1])) as ScenarioPayload;
    return obj && typeof obj === 'object' ? obj : null;
  } catch {
    return null;
  }
}

const HELD_KEYS: HeldKeyId[] = ['rsaPublic', 'hmac', 'ecPublic'];
const VIEWS: TokenView[] = ['raw', 'decoded', 'diff'];
const SCENARIOS: ScenarioCode[] = ['genuine', 'none', 'confusion', 'tamper', 'token'];

async function applyScenario(p: ScenarioPayload): Promise<void> {
  state.mode = p.m === 'v' ? 'vulnerable' : 'correct';
  if (Array.isArray(p.a)) {
    const algs = p.a.filter((x): x is AlgName => isAlgName(x));
    state.acceptedAlgs = new Set<AlgName>(algs);
  }
  if (HELD_KEYS.includes(p.k as HeldKeyId)) state.heldKey = p.k as HeldKeyId;
  if (VIEWS.includes(p.v as TokenView)) state.view = p.v as TokenView;
  state.compare = p.cmp === 1;
  state.scenario = SCENARIOS.includes(p.s) ? p.s : 'genuine';

  switch (state.scenario) {
    case 'none': {
      const r = attackAlgNone(state.baseToken);
      state.currentToken = r.forgedToken;
      state.explanation = r.explanation;
      break;
    }
    case 'confusion': {
      const r = await attackKeyConfusion(state.baseToken, state.keys.rsaPublicKeyPem);
      state.currentToken = r.forgedToken;
      state.explanation = r.explanation;
      break;
    }
    case 'tamper': {
      const r = attackSilentTamper(state.baseToken);
      state.currentToken = r.forgedToken;
      state.explanation = r.explanation;
      break;
    }
    case 'token': {
      state.currentToken = typeof p.t === 'string' && p.t ? p.t : state.baseToken;
      state.explanation = undefined;
      break;
    }
    case 'genuine':
    default:
      state.currentToken = state.baseToken;
      state.explanation = undefined;
  }
}

// ---- Verification --------------------------------------------------------------

async function runVerification(): Promise<void> {
  const policy = buildPolicy();
  if (state.compare) {
    const [correct, vulnerable] = await Promise.all([
      verifyCorrect(state.currentToken, policy),
      verifyVulnerable(state.currentToken, policy),
    ]);
    state.compareResults = { correct, vulnerable };
    state.result = state.mode === 'correct' ? correct : vulnerable;
  } else {
    state.compareResults = undefined;
    state.result =
      state.mode === 'correct'
        ? await verifyCorrect(state.currentToken, policy)
        : await verifyVulnerable(state.currentToken, policy);
  }

  // Flash the policy panel when an invariant in the policy caught a forgery.
  state.flashPolicy =
    state.result.decision === 'reject' && !!state.result.invariantTriggered && state.mode === 'correct';

  renderPolicyPanel();
  renderResultPanel();
}

// ---- Token panel ---------------------------------------------------------------

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function renderTokenPanel(): void {
  const panel = root.querySelector('#token-panel')!;
  const decoded = decodeUnsafe(state.currentToken);

  const tabs = (['raw', 'decoded', 'diff'] as TokenView[])
    .map(
      (v) =>
        `<button class="tab" role="tab" data-action="view" data-view="${v}" aria-selected="${state.view === v}">${v}</button>`,
    )
    .join('');

  let body = '';
  if (state.view === 'raw') {
    const [h, p, s] = state.currentToken.split('.');
    body = `
      <div class="raw-token" tabindex="0" aria-label="Raw JWT">
<span class="seg-h">${esc(h ?? '')}</span><span class="dot">.</span><span class="seg-p">${esc(p ?? '')}</span><span class="dot">.</span><span class="seg-s">${esc(s ?? '')}</span></div>
      <div class="btn-row">
        <button class="btn secondary" data-action="copy">Copy token</button>
        <button class="btn secondary" data-action="paste-toggle">Paste / load a token…</button>
        <button class="btn secondary" data-action="reset">Reset to genuine token</button>
      </div>
      <div id="paste-area" hidden style="margin-top:.6rem">
        <label for="paste-input" style="font-size:.8rem;color:var(--muted)">Paste a compact JWS (header.payload.signature)</label>
        <textarea id="paste-input" rows="3" style="width:100%;font-family:monospace"></textarea>
        <div class="btn-row"><button class="btn" data-action="paste-apply">Inspect this token</button></div>
      </div>
      ${state.tokenError ? `<p class="form-error" role="alert">⚠ ${esc(state.tokenError)}</p>` : ''}`;
  } else if (state.view === 'decoded') {
    if (!decoded) {
      body = `<p class="hint">This token cannot be decoded (malformed base64url or JSON). The verifier will reject it at parse time — that is the fail-closed behaviour.</p>`;
    } else {
      const headerText = state.draftHeader ?? JSON.stringify(decoded.header, null, 2);
      const payloadText = state.draftPayload ?? JSON.stringify(decoded.claims, null, 2);
      body = `
      <div class="cards">
        <div class="card header">
          <div class="card-h" id="lbl-header">Header</div>
          <label for="ta-header">JSON — controls the <code>alg</code></label>
          <textarea id="ta-header" aria-labelledby="lbl-header" spellcheck="false">${esc(headerText)}</textarea>
        </div>
        <div class="card payload">
          <div class="card-h" id="lbl-payload">Payload (claims)</div>
          <label for="ta-payload">JSON — try setting <code>admin</code> or <code>exp</code></label>
          <textarea id="ta-payload" aria-labelledby="lbl-payload" spellcheck="false">${esc(payloadText)}</textarea>
        </div>
        <div class="card signature">
          <div class="card-h">Signature</div>
          <div class="sig-bytes">${decoded.sig ? esc(decoded.sig) : '(empty — unsecured / alg:none)'}</div>
        </div>
      </div>
      ${state.tokenError ? `<p class="form-error" role="alert">⚠ ${esc(state.tokenError)}</p>` : ''}
      <div class="btn-row">
        <button class="btn" data-action="resign">Re-sign genuinely (with held key's pair)</button>
        <button class="btn secondary" data-action="tamper">Apply edits, keep old signature (tamper)</button>
        <button class="btn secondary" data-action="reset">Reset</button>
      </div>
      <p class="hint">“Re-sign” produces a legitimately signed token for the alg in the header. “Apply edits, keep signature” is the silent-tamper move — watch it get rejected.</p>`;
    }
  } else {
    body = renderDiff();
  }

  panel.innerHTML = `
    <h2>1 · Token <span class="tip" title="The compact JWS under inspection.">ⓘ</span></h2>
    <div class="tabs" role="tablist" aria-label="Token views">${tabs}</div>
    <div role="tabpanel" aria-label="${state.view} view">${body}</div>
    <p class="notwhat">Not a JWE: this is JWS (signatures), not encryption — contents are readable by anyone. Keys &amp; tokens are generated in memory per session and never persisted.</p>`;
}

function renderDiff(): string {
  const base = decodeUnsafe(state.baseToken);
  const cur = decodeUnsafe(state.currentToken);
  if (!base || !cur) return `<p class="hint">Cannot diff — one side does not decode.</p>`;

  const rows: string[] = [];
  const addRows = (section: string, a: Record<string, unknown>, b: Record<string, unknown>) => {
    // Guard against pasted tokens whose header/payload JSON is null/array/scalar.
    a = a && typeof a === 'object' ? a : {};
    b = b && typeof b === 'object' ? b : {};
    const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
    for (const k of keys) {
      const inA = k in a, inB = k in b;
      const av = JSON.stringify(a[k]);
      const bv = JSON.stringify(b[k]);
      if (inA && inB && av === bv) continue;
      const cls = !inA ? 'added' : !inB ? 'removed' : 'changed';
      rows.push(
        `<tr class="diff-row ${cls}"><td>${section}.${esc(k)}</td><td class="diff-old">${esc(inA ? av : '—')}</td><td class="diff-new">${esc(inB ? bv : '—')}</td></tr>`,
      );
    }
  };
  addRows('header', base.header as Record<string, unknown>, cur.header as Record<string, unknown>);
  addRows('claims', base.claims as Record<string, unknown>, cur.claims as Record<string, unknown>);
  const sigChanged = base.sig !== cur.sig;
  rows.push(
    `<tr class="diff-row ${sigChanged ? 'changed' : ''}"><td>signature</td><td class="diff-old">${sigChanged ? 'changed' : 'same'}</td><td class="diff-new">${cur.sig ? esc(cur.sig.slice(0, 24)) + '…' : '(empty)'}</td></tr>`,
  );

  if (rows.length === 1 && !sigChanged) {
    return `<p class="hint">No differences from the genuine base token yet. Mutate a claim or launch an attack.</p>`;
  }
  return `
    <p class="hint">Differences between the genuine base token and the token under inspection. “I tampered and it still verified” becomes visible here.</p>
    <div class="table-wrap">
      <table class="diff-table">
        <thead><tr><th>field</th><th>genuine</th><th>current</th></tr></thead>
        <tbody>${rows.join('')}</tbody>
      </table>
    </div>`;
}

// ---- Policy panel --------------------------------------------------------------

function renderPolicyPanel(): void {
  const panel = root.querySelector('#policy-panel')!;
  const algs: AlgName[] = ['HS256', 'RS256', 'ES256', 'none'];
  const checks = algs
    .map(
      (a) =>
        `<label><input type="checkbox" data-action="alg" data-alg="${a}" ${state.acceptedAlgs.has(a) ? 'checked' : ''}> ${a}${a === 'none' ? ' ⚠' : ''}</label>`,
    )
    .join('');

  const keyOpts: Array<[HeldKeyId, string]> = [
    ['rsaPublic', 'RSA public key (RS256)'],
    ['hmac', 'HMAC shared secret (HS256)'],
    ['ecPublic', 'EC public key (ES256)'],
  ];
  const radios = keyOpts
    .map(
      ([id, label]) =>
        `<label><input type="radio" name="heldkey" data-action="heldkey" data-key="${id}" ${state.heldKey === id ? 'checked' : ''}> ${label}</label>`,
    )
    .join('');

  panel.innerHTML = `
    <h2>2 · Verifier policy <span class="tip" title="The conceptual heart: the application — not the token — decides what is acceptable.">ⓘ</span></h2>
    <p class="hint">The verifier never reads the token's <code>alg</code> to choose a routine. The application sets the policy below; the token is judged against it.</p>

    <fieldset id="alg-fieldset" class="${state.flashPolicy ? 'flash' : ''}">
      <legend>Accepted algorithms (required allowlist — empty = accept nothing)</legend>
      <div class="checks">${checks}</div>
    </fieldset>

    <fieldset>
      <legend>Key the verifier holds</legend>
      <div class="radios">${radios}</div>
    </fieldset>

    <fieldset>
      <legend>Verifier implementation</legend>
      <div class="mode-toggle">
        <div class="seg" role="group" aria-label="Verifier mode">
          <button data-action="mode" data-mode="correct" aria-pressed="${state.mode === 'correct'}">✓ Correct</button>
          <button data-action="mode" data-mode="vulnerable" aria-pressed="${state.mode === 'vulnerable'}">⚠ Vulnerable</button>
        </div>
        <span class="hint" style="margin:0">Flip this and re-run the same token — that's the “aha”.</span>
      </div>
      <div class="vuln-warning ${state.mode === 'vulnerable' ? 'on' : ''}">
        ⚠ This is the DELIBERATELY BROKEN verifier. It picks its routine from the token's <code>alg</code> and will use a public key as an HMAC secret. Never ship this.
      </div>
    </fieldset>

    <div class="btn-row">
      <button class="btn" data-action="verify">Verify this token ▶</button>
    </div>

    <details class="defense-rules">
      <summary>Real-world defense rules (what these invariants mean in production)</summary>
      <ol>
        <li><strong>Never derive accepted algorithms from the token header.</strong> The application supplies the allowlist; the token does not get to name its own algorithm.</li>
        <li><strong>Bind each key to exactly the algorithms it may verify.</strong> An RSA public key must never be reachable from an HMAC code path — enforce it with types, not discipline.</li>
        <li><strong>Disable <code>none</code></strong> unless the surrounding protocol explicitly requires an unsecured JWS.</li>
        <li><strong>Reject before claims are trusted.</strong> Validate the signature first; check <code>exp</code>/<code>nbf</code> separately and never conflate "valid signature" with "valid token".</li>
      </ol>
    </details>

    <p class="notwhat">Not in scope: brute-forcing the HS256 secret. That's password strength, not a JWT structural flaw.</p>`;

  if (state.flashPolicy) {
    state.flashPolicy = false; // one-shot
  }
}

// ---- Result panel --------------------------------------------------------------

function pill(label: string, status: 'valid' | 'invalid' | 'not-checked'): string {
  const cls = status === 'valid' ? 'valid' : status === 'invalid' ? 'invalid' : 'notchecked';
  const icon = status === 'valid' ? '✓ ' : status === 'invalid' ? '⚠ ' : '· ';
  return `<span class="status-row"><span class="k">${label}</span><span class="pill ${cls}">${icon}${status}</span></span>`;
}

function bannerParts(r: VerifyResult): { cls: string; icon: string; headline: string } {
  // Colour tracks SYSTEM INTEGRITY, not the raw accept/reject.
  if (r.systemIntegrity === 'fooled' && r.decision === 'accept') {
    return { cls: 'forged', icon: '⚠', headline: 'FORGED TOKEN ACCEPTED' };
  }
  if (r.decision === 'accept') {
    return { cls: 'valid', icon: '✓', headline: 'Valid signature — all checks passed' };
  }
  return { cls: 'rejected', icon: '✓', headline: state.explanation ? 'REJECTED AS EXPECTED' : 'Rejected' };
}

function traceIcon(status: TraceStep['status']): string {
  return status === 'pass' ? '✓' : status === 'fail' ? '✗' : status === 'skip' ? '·' : '•';
}

function renderTrace(trace: TraceStep[]): string {
  if (!trace || trace.length === 0) return '';
  const rows = trace
    .map(
      (s) => `
      <li class="trace-step ${s.status}${s.decisive ? ' decisive' : ''}">
        <span class="trace-icon" aria-hidden="true">${traceIcon(s.status)}</span>
        <span class="trace-body">
          <span class="trace-label">${esc(s.label)}${s.decisive ? ' <span class="trace-tag">← decided here</span>' : ''}</span>
          <span class="trace-detail">${esc(s.detail)}</span>
        </span>
      </li>`,
    )
    .join('');
  return `<div class="trace"><h4>Decision trace <span class="hint" style="margin:0">(token alg → policy → key type → signature → claims)</span></h4><ol class="trace-list">${rows}</ol></div>`;
}

function causalBlock(): string {
  if (!state.explanation) return '';
  const ex = state.explanation;
  return `
    <div class="causal">
      <h4>${esc(ex.title)} — causal chain</h4>
      <div class="chain">${esc(ex.whyItPassed)}</div>
      <ul>
        <li><strong>Verifier mistake:</strong> ${esc(ex.verifierMistake)}</li>
        <li><strong>Correct verifier defends by:</strong> ${esc(ex.correctDefense)}</li>
        ${(ex.detail ?? []).map((d) => `<li><code>${esc(d)}</code></li>`).join('')}
      </ul>
    </div>`;
}

function renderResultColumn(r: VerifyResult, title: string): string {
  const b = bannerParts(r);
  return `
    <div class="result-col">
      <h3 class="col-title">${esc(title)}</h3>
      <div class="banner ${b.cls}">
        <div class="icon" aria-hidden="true">${b.icon}</div>
        <div><p class="headline">${b.icon} ${esc(b.headline)}</p><p class="reason">${esc(r.reason)}</p></div>
      </div>
      <div class="status-rows">
        ${pill('Signature', r.signature)}
        ${pill('Claims (exp/nbf)', r.claims)}
        <div class="status-row"><span class="k">Claimed alg</span><span>${esc(String(r.claimedAlg ?? '—'))}</span></div>
        ${r.invariantTriggered ? `<div class="status-row"><span class="k">Invariant</span><span>${esc(r.invariantTriggered)}</span></div>` : ''}
      </div>
      ${renderTrace(r.trace)}
    </div>`;
}

/** Plain-text summary suitable for a slide, classroom note, or bug report. */
function buildSummary(): string {
  const r = state.result;
  if (!r) return '';
  const lines: string[] = ['JWT Forge — what just happened'];
  if (state.explanation) lines.push(`Scenario: ${state.explanation.title}`);
  lines.push(`Token claimed alg: ${r.claimedAlg ?? '—'}`);
  if (state.compareResults) {
    const c = state.compareResults.correct;
    const v = state.compareResults.vulnerable;
    lines.push(`Correct verifier:    ${c.decision.toUpperCase()} — ${c.reason}`);
    lines.push(`Vulnerable verifier: ${v.decision.toUpperCase()}${v.systemIntegrity === 'fooled' ? ' (FOOLED)' : ''} — ${v.reason}`);
  } else {
    lines.push(`Verifier: ${state.mode}`);
    lines.push(`Decision: ${r.decision.toUpperCase()}${r.systemIntegrity === 'fooled' ? ' (FOOLED)' : ''}`);
    lines.push(`Signature: ${r.signature}; Claims: ${r.claims}`);
    lines.push(`Reason: ${r.reason}`);
    if (r.invariantTriggered) lines.push(`Invariant: ${r.invariantTriggered}`);
  }
  if (state.explanation) lines.push(`Why: ${state.explanation.whyItPassed}`);
  return lines.join('\n');
}

function renderResultPanel(): void {
  const panel = root.querySelector('#result-panel')!;
  const r = state.result;
  if (!r) {
    panel.innerHTML = `<h2>3 · Result</h2><p class="hint">Set a policy and press “Verify this token”.</p>`;
    return;
  }

  if (state.compareResults) {
    const { correct, vulnerable } = state.compareResults;
    const srSummary = `Correct verifier ${correct.decision}s; Vulnerable verifier ${vulnerable.decision}s${vulnerable.systemIntegrity === 'fooled' ? ' and is fooled' : ''}.`;
    panel.innerHTML = `
      <h2>3 · Result — side by side</h2>
      <p class="sr-only" role="status" aria-live="polite">${esc(srSummary)}</p>
      <p class="hint">Same token, same policy, both verifiers. The difference is entirely in the implementation.</p>
      <div class="compare-grid">
        ${renderResultColumn(correct, '✓ Correct verifier')}
        ${renderResultColumn(vulnerable, '⚠ Vulnerable verifier')}
      </div>
      ${causalBlock()}
      <div class="btn-row">
        <button class="btn secondary" data-action="compare-off">← Back to single verifier</button>
        <button class="btn secondary" data-action="copy-summary">Copy summary</button>
        <button class="btn secondary" data-action="share">🔗 Copy share link</button>
      </div>`;
    return;
  }

  const b = bannerParts(r);
  const invariantLine = r.invariantTriggered
    ? `<div class="status-row"><span class="k">Invariant that caught it</span><span>${esc(r.invariantTriggered)}</span></div>`
    : '';
  const contrastMode = state.mode === 'correct' ? 'vulnerable' : 'correct';
  const contrastLabel =
    contrastMode === 'correct' ? '▶ Now try the Correct verifier' : '▶ Now try the Vulnerable verifier';

  panel.innerHTML = `
    <h2>3 · Result</h2>
    <div class="banner ${b.cls}" role="status" aria-live="polite">
      <div class="icon" aria-hidden="true">${b.icon}</div>
      <div>
        <p class="headline">${b.icon} ${esc(b.headline)}</p>
        <p class="reason">${esc(r.reason)}</p>
      </div>
    </div>
    <div class="status-rows">
      ${pill('Signature check', r.signature)}
      ${pill('Claim check (exp/nbf)', r.claims)}
      ${r.claimDetail ? `<div class="status-row"><span class="k">Claim detail</span><span>${esc(r.claimDetail)}</span></div>` : ''}
      <div class="status-row"><span class="k">Verifier mode</span><span>${state.mode === 'correct' ? '✓ Correct' : '⚠ Vulnerable'}</span></div>
      <div class="status-row"><span class="k">Token claimed alg</span><span>${esc(String(r.claimedAlg ?? '—'))}</span></div>
      ${invariantLine}
    </div>
    ${renderTrace(r.trace)}
    ${causalBlock()}
    <div class="btn-row">
      <button class="btn contrast" data-action="contrast" data-mode="${contrastMode}">${contrastLabel}</button>
      <button class="btn secondary" data-action="compare-on">⇄ Compare both side by side</button>
      <button class="btn secondary" data-action="copy-summary">Copy summary</button>
      <button class="btn secondary" data-action="share">🔗 Copy share link</button>
    </div>`;
}

// ---- Attacks -------------------------------------------------------------------

async function launchAttack(which: 'none' | 'confusion' | 'tamper'): Promise<void> {
  // Each attack scripts both the mutation AND a realistic verifier state, then we run
  // the Vulnerable verifier first so the contrast button reveals the Correct rejection.
  if (which === 'none') {
    const r = attackAlgNone(state.baseToken);
    state.currentToken = r.forgedToken;
    state.explanation = r.explanation;
    // Realistic app policy: it only ever intended RS256. `none` is NOT allowlisted.
    state.acceptedAlgs = new Set<AlgName>(['RS256']);
    state.heldKey = 'rsaPublic';
  } else if (which === 'confusion') {
    const r = await attackKeyConfusion(state.baseToken, state.keys.rsaPublicKeyPem);
    state.currentToken = r.forgedToken;
    state.explanation = r.explanation;
    state.acceptedAlgs = new Set<AlgName>(['RS256']);
    state.heldKey = 'rsaPublic';
  } else {
    const r = attackSilentTamper(state.baseToken);
    state.currentToken = r.forgedToken;
    state.explanation = r.explanation;
    state.acceptedAlgs = new Set<AlgName>(['RS256']);
    state.heldKey = 'rsaPublic';
  }
  state.scenario = which;
  state.mode = 'vulnerable';
  state.view = 'decoded';
  state.compare = false;
  clearDrafts();
  renderTokenPanel();
  await runVerification();
  const rp = root.querySelector('#result-panel') as HTMLElement | null;
  if (rp && typeof rp.scrollIntoView === 'function') {
    rp.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'nearest' });
  }
}

// ---- Token mutation actions ----------------------------------------------------

function signingKeyForAlg(alg: AlgName): SigningKey | null {
  switch (alg) {
    case 'HS256': return state.keys.hmac;
    case 'RS256': return state.keys.rsaPrivate;
    case 'ES256': return state.keys.ecPrivate;
    case 'none': return null;
  }
}

async function resign(): Promise<void> {
  const headerTa = root.querySelector<HTMLTextAreaElement>('#ta-header');
  const payloadTa = root.querySelector<HTMLTextAreaElement>('#ta-payload');
  if (!headerTa || !payloadTa) return;
  let header: JwtHeader, claims: JwtClaims;
  try {
    header = JSON.parse(headerTa.value);
    claims = JSON.parse(payloadTa.value);
  } catch {
    state.tokenError = 'Header or payload is not valid JSON.';
    renderTokenPanel();
    return;
  }
  const key = signingKeyForAlg(header.alg);
  if (!key) {
    state.tokenError = 'alg:none has no signing key — use an attack launcher to build an unsecured token.';
    renderTokenPanel();
    return;
  }
  state.currentToken = await sign(header, claims, key);
  state.explanation = undefined;
  state.scenario = 'token';
  clearDrafts();
  renderTokenPanel();
  await runVerification();
}

function tamper(): void {
  const headerTa = root.querySelector<HTMLTextAreaElement>('#ta-header');
  const payloadTa = root.querySelector<HTMLTextAreaElement>('#ta-payload');
  if (!headerTa || !payloadTa) return;
  let header: unknown, claims: unknown;
  try {
    header = JSON.parse(headerTa.value);
    claims = JSON.parse(payloadTa.value);
  } catch {
    state.tokenError = 'Header or payload is not valid JSON.';
    renderTokenPanel();
    return;
  }
  const oldSig = state.currentToken.split('.')[2] ?? '';
  state.currentToken = `${base64urlEncodeString(JSON.stringify(header))}.${base64urlEncodeString(JSON.stringify(claims))}.${oldSig}`;
  state.scenario = 'token';
  clearDrafts();
  state.explanation = {
    title: 'manual tamper',
    claimedAlg: (header as JwtHeader).alg,
    verifierMistake: 'none — edits were applied without re-signing',
    whyItPassed: 'edited payload  →  signature unchanged  →  signature no longer matches content  →  rejected',
    correctDefense: 'the signature is recomputed over header.payload and no longer matches',
  };
  renderTokenPanel();
  void runVerification();
}

// ---- Guided lesson tour --------------------------------------------------------

interface TourStep {
  title: string;
  body: string;
  /** Mutate state to set up this step (token, mode, policy, compare). */
  setup: () => void | Promise<void>;
}

function setForgeryScene(scenario: ScenarioCode): void {
  state.acceptedAlgs = new Set<AlgName>(['RS256']);
  state.heldKey = 'rsaPublic';
  state.compare = false;
  state.view = 'decoded';
  state.scenario = scenario;
}

const tourSteps: TourStep[] = [
  {
    title: 'Start with a genuine, valid token',
    body: 'This RS256 token was signed with the real private key. The Correct verifier accepts it — calm green. Notice the decision trace passes every step.',
    setup: () => {
      state.currentToken = state.baseToken;
      state.explanation = undefined;
      setForgeryScene('genuine');
      state.mode = 'correct';
    },
  },
  {
    title: 'Lesson 1 — tampering without a bug fails',
    body: 'We change a claim to admin:true but keep the old signature. Even the Vulnerable verifier rejects it: the signature is bound to the original content. No structural flaw, no forgery.',
    setup: () => {
      const r = attackSilentTamper(state.baseToken);
      state.currentToken = r.forgedToken;
      state.explanation = r.explanation;
      setForgeryScene('tamper');
      state.mode = 'vulnerable';
    },
  },
  {
    title: 'Lesson 2 — alg:none, against the Vulnerable verifier',
    body: 'Strip the signature and set alg:none. The Vulnerable verifier reads the alg from the token, picks the "none" routine, and checks no signature at all → FORGED TOKEN ACCEPTED (red).',
    setup: () => {
      const r = attackAlgNone(state.baseToken);
      state.currentToken = r.forgedToken;
      state.explanation = r.explanation;
      setForgeryScene('none');
      state.mode = 'vulnerable';
    },
  },
  {
    title: 'Lesson 2 — same token, the Correct verifier',
    body: 'Identical token. The Correct verifier checks its allowlist first: "none" is not on it, so it never even chooses a routine. REJECTED AS EXPECTED (green). The trace shows exactly where it stops.',
    setup: () => {
      const r = attackAlgNone(state.baseToken);
      state.currentToken = r.forgedToken;
      state.explanation = r.explanation;
      setForgeryScene('none');
      state.mode = 'correct';
    },
  },
  {
    title: 'Lesson 3 — RS/HS confusion, against the Vulnerable verifier',
    body: 'Re-sign with HS256, using the RSA PUBLIC key (a value anyone can read) as the HMAC secret. The Vulnerable verifier runs HMAC with that same public key → accepted (red).',
    setup: async () => {
      const r = await attackKeyConfusion(state.baseToken, state.keys.rsaPublicKeyPem);
      state.currentToken = r.forgedToken;
      state.explanation = r.explanation;
      setForgeryScene('confusion');
      state.mode = 'vulnerable';
    },
  },
  {
    title: 'Lesson 3 — same token, the Correct verifier',
    body: 'The Correct verifier expects RS256 and holds an RsaPublicKey. HS256 is not allowlisted, and an RSA public key is type-incompatible with the HMAC path — confusion is literally unrepresentable. Rejected (green).',
    setup: async () => {
      const r = await attackKeyConfusion(state.baseToken, state.keys.rsaPublicKeyPem);
      state.currentToken = r.forgedToken;
      state.explanation = r.explanation;
      setForgeryScene('confusion');
      state.mode = 'correct';
    },
  },
  {
    title: 'Lesson 4 — the defense is policy + key binding',
    body: 'Same forged token, both verifiers side by side. The only difference is the implementation: the Correct one never lets the attacker-controlled header choose the algorithm or the key. That single rule defeats both attacks.',
    setup: async () => {
      const r = await attackKeyConfusion(state.baseToken, state.keys.rsaPublicKeyPem);
      state.currentToken = r.forgedToken;
      state.explanation = r.explanation;
      setForgeryScene('confusion');
      state.compare = true;
    },
  },
];

async function applyTourStep(index: number): Promise<void> {
  if (index < 0 || index >= tourSteps.length) return;
  state.tourIndex = index;
  await tourSteps[index].setup();
  clearDrafts();
  renderTour();
  renderTokenPanel();
  await runVerification();
  const tourEl = root.querySelector('#tour') as HTMLElement | null;
  if (tourEl && typeof tourEl.scrollIntoView === 'function') {
    tourEl.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'nearest' });
  }
}

function renderTour(): void {
  const el = root.querySelector('#tour')!;
  if (state.tourIndex === undefined) {
    el.innerHTML = `
      <h2>Guided tour <span class="hint" style="margin:0">— 7 steps, ~90 seconds</span></h2>
      <p class="hint">New to JWTs? Walk the core lesson: genuine token → forge → vulnerable accepts → correct rejects.</p>
      <div class="btn-row"><button class="btn" data-action="tour-start">▶ Start guided tour</button></div>`;
    return;
  }
  const i = state.tourIndex;
  const step = tourSteps[i];
  const isLast = i === tourSteps.length - 1;
  el.innerHTML = `
    <h2>Guided tour <span class="hint" style="margin:0">— step ${i + 1} of ${tourSteps.length}</span></h2>
    <div class="tour-step" role="status" aria-live="polite">
      <h3>${esc(step.title)}</h3>
      <p>${esc(step.body)}</p>
    </div>
    <div class="tour-progress" aria-hidden="true">${tourSteps
      .map((_, n) => `<span class="dot ${n === i ? 'on' : n < i ? 'done' : ''}"></span>`)
      .join('')}</div>
    <div class="btn-row">
      <button class="btn secondary" data-action="tour-prev" ${i === 0 ? 'disabled' : ''}>← Previous</button>
      <button class="btn" data-action="tour-next">${isLast ? 'Finish ✓' : 'Next →'}</button>
      <button class="btn secondary" data-action="tour-exit">Exit tour</button>
    </div>`;
}

// ---- Event wiring --------------------------------------------------------------

function onClick(e: MouseEvent): void {
  const target = (e.target as HTMLElement).closest<HTMLElement>('[data-action]');
  if (!target) return;
  const action = target.dataset.action;

  switch (action) {
    case 'view':
      state.view = target.dataset.view as TokenView;
      renderTokenPanel();
      break;
    case 'copy':
      void navigator.clipboard?.writeText(state.currentToken);
      target.textContent = 'Copied ✓';
      setTimeout(() => (target.textContent = 'Copy token'), 1200);
      break;
    case 'paste-toggle': {
      const area = root.querySelector<HTMLElement>('#paste-area');
      if (area) area.hidden = !area.hidden;
      break;
    }
    case 'paste-apply': {
      const input = root.querySelector<HTMLTextAreaElement>('#paste-input');
      if (input && input.value.trim()) {
        state.currentToken = input.value.trim();
        state.explanation = undefined;
        state.scenario = 'token';
        clearDrafts();
        renderTokenPanel();
        void runVerification();
      }
      break;
    }
    case 'reset':
      state.currentToken = state.baseToken;
      state.explanation = undefined;
      state.scenario = 'genuine';
      clearDrafts();
      renderTokenPanel();
      void runVerification();
      break;
    case 'resign':
      void resign();
      break;
    case 'tamper':
      tamper();
      break;
    case 'alg': {
      const a = target.dataset.alg as AlgName;
      const cb = target as HTMLInputElement;
      if (cb.checked) state.acceptedAlgs.add(a);
      else state.acceptedAlgs.delete(a);
      void runVerification();
      break;
    }
    case 'heldkey':
      state.heldKey = target.dataset.key as HeldKeyId;
      void runVerification();
      break;
    case 'mode':
      state.mode = target.dataset.mode as 'correct' | 'vulnerable';
      void runVerification();
      break;
    case 'contrast':
      state.mode = target.dataset.mode as 'correct' | 'vulnerable';
      void runVerification();
      break;
    case 'compare-on':
      state.compare = true;
      void runVerification();
      break;
    case 'compare-off':
      state.compare = false;
      void runVerification();
      break;
    case 'copy-summary': {
      void navigator.clipboard?.writeText(buildSummary());
      target.textContent = 'Copied ✓';
      setTimeout(() => (target.textContent = 'Copy summary'), 1200);
      break;
    }
    case 'share': {
      const url = buildShareUrl();
      try {
        location.hash = url.split('#')[1] ?? '';
      } catch {
        /* hash assignment can throw in non-browser test envs; ignore */
      }
      void navigator.clipboard?.writeText(url);
      target.textContent = 'Link copied ✓';
      setTimeout(() => (target.textContent = '🔗 Copy share link'), 1400);
      break;
    }
    case 'verify':
      void runVerification();
      break;
    case 'attack-none':
      void launchAttack('none');
      break;
    case 'attack-confusion':
      void launchAttack('confusion');
      break;
    case 'attack-tamper':
      void launchAttack('tamper');
      break;
    case 'tour-start':
      void applyTourStep(0);
      break;
    case 'tour-prev':
      void applyTourStep((state.tourIndex ?? 0) - 1);
      break;
    case 'tour-next':
      if (state.tourIndex !== undefined && state.tourIndex >= tourSteps.length - 1) {
        state.tourIndex = undefined;
        renderTour();
      } else {
        void applyTourStep((state.tourIndex ?? -1) + 1);
      }
      break;
    case 'tour-exit':
      state.tourIndex = undefined;
      renderTour();
      break;
  }
}

/** Capture in-progress JSON edits so switching token tabs doesn't discard them. */
function onInput(e: Event): void {
  const t = e.target as HTMLElement;
  if (t.id === 'ta-header') state.draftHeader = (t as HTMLTextAreaElement).value;
  else if (t.id === 'ta-payload') state.draftPayload = (t as HTMLTextAreaElement).value;
}

// ---- Bootstrap -----------------------------------------------------------------

export async function mountApp(el: HTMLElement): Promise<void> {
  root = el;
  el.innerHTML = `
    <div class="lab">
      <div class="intro">
        <h1>JWT Forge — a JWS signature-verification playground</h1>
        <p>Decode a token, mutate it, swap its algorithm, and run two canonical structural attacks
        (<code>alg:none</code> and RS/HS key confusion) against a <strong>Correct</strong> verifier and a
        deliberately <strong>Vulnerable</strong> one. Colour tracks <em>system integrity</em>: red means a
        forgery was accepted, green means the system held. Everything runs in your browser; keys are
        generated per session and never leave the page.</p>
      </div>
      <section class="panel" id="tour"></section>
      <section class="panel" id="token-panel"></section>
      <section class="panel" id="policy-panel"></section>
      <section class="panel" id="result-panel"></section>
      <section class="panel" id="attacks">
        <h2>Attack launchers</h2>
        <p class="hint">Each scripts the forgery and a realistic verifier state, runs the Vulnerable verifier,
          then offers a one-click switch to the Correct verifier.</p>
        <div class="launchers">
          <div class="launcher-card">
            <h3>alg:none</h3>
            <p>Strip the signature, set <code>alg:none</code>, escalate <code>admin:true</code>.</p>
            <button class="btn" data-action="attack-none">Launch alg:none</button>
          </div>
          <div class="launcher-card">
            <h3>Key confusion (RS→HS)</h3>
            <p>Re-sign with HS256 using the RSA <em>public</em> key as the MAC secret.</p>
            <button class="btn" data-action="attack-confusion">Launch key confusion</button>
          </div>
          <div class="launcher-card">
            <h3>Silent tamper (control)</h3>
            <p>Edit a claim, keep the old signature. Should fail everywhere.</p>
            <button class="btn" data-action="attack-tamper">Launch silent tamper</button>
          </div>
        </div>
      </section>
    </div>`;

  el.addEventListener('click', onClick);
  el.addEventListener('input', onInput);

  const keys = await generateSessionKeys();
  const nowSec = Math.floor(Date.now() / 1000);
  const baseToken = await sign(
    {},
    { sub: 'user-123', name: 'Ada Lovelace', admin: false, iat: nowSec - 60, exp: nowSec + 3600 },
    keys.rsaPrivate,
  );

  state = {
    keys,
    baseToken,
    currentToken: baseToken,
    view: 'decoded',
    acceptedAlgs: new Set<AlgName>(['RS256']),
    heldKey: 'rsaPublic',
    mode: 'correct',
    flashPolicy: false,
    compare: false,
    scenario: 'genuine',
  };

  // Restore a shared scenario from the URL hash, if present (#s=<base64url>).
  const shared = readScenarioHash();
  if (shared) {
    try {
      await applyScenario(shared);
    } catch {
      /* malformed link → fall back to the default genuine scenario */
    }
  }

  renderTour();
  renderTokenPanel();
  renderPolicyPanel();
  await runVerification();
}
