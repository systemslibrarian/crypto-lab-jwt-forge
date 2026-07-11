import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Scans the full page with every collapsible expanded,
 * in both the dark (default) and light themes. Modeled on the ascon lab gate.
 *
 * This lab renders several mutually-exclusive views into shared panels: the
 * Token panel has raw/decoded/diff tabs, and the Result panel has a
 * single-verifier vs side-by-side compare mode. Each test iterates those views
 * so axe sees every rendered surface, not just the default one.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function neutralizeMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*, *::before, *::after {
      animation: none !important;
      transition: none !important;
      opacity: 1 !important;
    }`,
  });
}

async function revealAll(page: Page): Promise<void> {
  // Open every <details>, reveal [hidden] / display:none panels so axe can
  // measure everything that a user could reveal.
  await page.evaluate(() => {
    for (const details of Array.from(document.querySelectorAll('details'))) {
      (details as HTMLDetailsElement).open = true;
    }
    for (const el of Array.from(document.querySelectorAll('[hidden]'))) {
      el.removeAttribute('hidden');
    }
    for (const el of Array.from(
      document.querySelectorAll<HTMLElement>('[style*="display: none"], [style*="display:none"]'),
    )) {
      el.style.display = '';
    }
  });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

/** Wait for the app to render its interactive shell (keys are generated async). */
async function ready(page: Page): Promise<void> {
  await page.locator('#token-panel .tabs').waitFor();
  await page.locator('#result-panel .banner, #result-panel .hint').first().waitFor();
}

/**
 * Scan the default view plus each Token-view tab and the side-by-side compare
 * mode, re-revealing collapsibles between renders (each render rebuilds panels).
 */
async function scanAllSurfaces(page: Page): Promise<void> {
  await neutralizeMotion(page);
  await revealAll(page);
  await scan(page);

  for (const view of ['raw', 'diff', 'decoded']) {
    await page.locator(`.tab[data-view="${view}"]`).click();
    await revealAll(page);
    await scan(page);
  }

  // Side-by-side compare mode renders a distinct result surface.
  const compareOn = page.locator('[data-action="compare-on"]').first();
  if (await compareOn.count()) {
    await compareOn.click();
    await page.locator('.compare-grid').waitFor();
    await revealAll(page);
    await scan(page);
  }
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await ready(page);
  await scanAllSurfaces(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await ready(page);
  await scanAllSurfaces(page);
});
