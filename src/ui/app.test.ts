// @vitest-environment happy-dom
//
// End-to-end UI verification in a real DOM. This exercises mountApp, the attack
// launchers, the Correct/Vulnerable mode contrast, and the colour-by-system-integrity
// banner mapping — the parts the node-only crypto tests do not cover.

import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { webcrypto } from 'node:crypto';
import { mountApp } from './app.ts';

beforeAll(() => {
  // happy-dom does not ship a WebCrypto SubtleCrypto; borrow Node's.
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
  }
});

let app: HTMLElement;

beforeEach(() => {
  try {
    location.hash = '';
  } catch {
    /* ignore */
  }
  document.body.innerHTML = '<div id="app"></div>';
  app = document.getElementById('app')!;
});

async function waitFor(predicate: () => boolean, ms = 5000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < ms) {
    if (predicate()) return;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error('timed out waiting for condition');
}

function banner(): HTMLElement | null {
  return app.querySelector('.banner');
}
function resultText(): string {
  return app.querySelector('#result-panel')?.textContent ?? '';
}
function click(selector: string): void {
  const el = app.querySelector<HTMLElement>(selector);
  if (!el) throw new Error(`no element for ${selector}`);
  el.click();
}

describe('UI: initial state', () => {
  it('mounts and shows a calm valid result for the genuine token', async () => {
    await mountApp(app);
    await waitFor(() => !!banner());
    expect(banner()!.classList.contains('valid')).toBe(true);
    expect(resultText()).toMatch(/Valid signature/i);
  });
});

describe('UI: alg:none attack', () => {
  it('Vulnerable accepts (red), Correct rejects (green) on the same token', async () => {
    await mountApp(app);
    await waitFor(() => !!banner());

    click('[data-action="attack-none"]');
    await waitFor(() => banner()!.classList.contains('forged'));
    expect(resultText()).toMatch(/FORGED TOKEN ACCEPTED/);

    click('[data-action="contrast"][data-mode="correct"]');
    await waitFor(() => banner()!.classList.contains('rejected'));
    expect(resultText()).toMatch(/REJECTED AS EXPECTED/);
    expect(resultText()).toMatch(/allowlist/i);
  });
});

describe('UI: key confusion attack', () => {
  it('Vulnerable accepts (red), Correct rejects (green)', async () => {
    await mountApp(app);
    await waitFor(() => !!banner());

    click('[data-action="attack-confusion"]');
    await waitFor(() => banner()!.classList.contains('forged'));
    expect(resultText()).toMatch(/FORGED TOKEN ACCEPTED/);

    click('[data-action="contrast"][data-mode="correct"]');
    await waitFor(() => banner()!.classList.contains('rejected'));
    expect(resultText()).toMatch(/REJECTED AS EXPECTED/);
  });
});

describe('UI: silent tamper control', () => {
  it('is rejected by both verifiers (never red)', async () => {
    await mountApp(app);
    await waitFor(() => !!banner());

    click('[data-action="attack-tamper"]');
    await waitFor(() => banner()!.classList.contains('rejected'));
    expect(banner()!.classList.contains('forged')).toBe(false);

    click('[data-action="contrast"][data-mode="correct"]');
    await waitFor(() => banner()!.classList.contains('rejected'));
    expect(resultText()).toMatch(/reject/i);
  });
});

describe('UI: side-by-side compare', () => {
  it('shows Correct rejecting and Vulnerable being fooled on one token', async () => {
    await mountApp(app);
    await waitFor(() => !!banner());

    click('[data-action="attack-confusion"]');
    await waitFor(() => banner()!.classList.contains('forged'));

    click('[data-action="compare-on"]');
    await waitFor(() => app.querySelectorAll('.result-col').length === 2);

    const cols = app.querySelectorAll('.result-col');
    // Column order is Correct, then Vulnerable.
    expect(cols[0].querySelector('.banner')!.classList.contains('rejected')).toBe(true);
    expect(cols[1].querySelector('.banner')!.classList.contains('forged')).toBe(true);
    // Each column renders a decision trace.
    expect(cols[0].querySelector('.trace-list')).not.toBeNull();
  });
});

describe('UI: decision trace', () => {
  it('renders a trace with exactly one decisive step for a rejected forgery', async () => {
    await mountApp(app);
    await waitFor(() => !!banner());
    click('[data-action="attack-none"]');
    await waitFor(() => banner()!.classList.contains('forged'));
    click('[data-action="contrast"][data-mode="correct"]');
    await waitFor(() => banner()!.classList.contains('rejected'));
    expect(app.querySelectorAll('.trace-step').length).toBeGreaterThan(0);
    expect(app.querySelectorAll('.trace-step.decisive').length).toBe(1);
  });
});

describe('UI: shareable scenario link', () => {
  it('round-trips a forged scenario through the URL hash into a fresh session', async () => {
    await mountApp(app);
    await waitFor(() => !!banner());

    click('[data-action="attack-confusion"]'); // confusion, vulnerable → forged
    await waitFor(() => banner()!.classList.contains('forged'));

    click('[data-action="share"]');
    expect(location.hash).toMatch(/^#s=/);

    // Remount in a fresh element + fresh session keys, same hash → scenario restores.
    document.body.innerHTML = '<div id="app"></div>';
    const app2 = document.getElementById('app')!;
    await mountApp(app2);
    await waitFor(() => {
      const b = app2.querySelector('.banner');
      return !!b && b.classList.contains('forged');
    });
    expect(app2.textContent).toMatch(/FORGED TOKEN ACCEPTED/);
  });
});

describe('UI: guided tour', () => {
  it('walks genuine → tamper → alg:none forged → correct reject', async () => {
    await mountApp(app);
    await waitFor(() => !!banner());

    click('[data-action="tour-start"]');
    await waitFor(() => banner()!.classList.contains('valid')); // step 1 genuine

    click('[data-action="tour-next"]'); // step 2 silent tamper (vulnerable, rejected)
    await waitFor(() => banner()!.classList.contains('rejected'));

    click('[data-action="tour-next"]'); // step 3 alg:none vulnerable (forged)
    await waitFor(() => banner()!.classList.contains('forged'));

    click('[data-action="tour-next"]'); // step 4 alg:none correct (rejected)
    await waitFor(() => banner()!.classList.contains('rejected'));
    expect(app.textContent).toMatch(/step 4 of 7/);
  });
});

describe('UI: token-view tabs preserve edits', () => {
  it('keeps draft JSON edits when switching tabs', async () => {
    await mountApp(app);
    await waitFor(() => !!banner());

    const ta = app.querySelector<HTMLTextAreaElement>('#ta-payload')!;
    ta.value = '{"edited":true}';
    ta.dispatchEvent(new Event('input', { bubbles: true }));

    click('[data-action="view"][data-view="raw"]');
    click('[data-action="view"][data-view="decoded"]');

    const ta2 = app.querySelector<HTMLTextAreaElement>('#ta-payload')!;
    expect(ta2.value).toBe('{"edited":true}');
  });
});
