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
