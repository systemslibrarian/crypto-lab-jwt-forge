import { test } from '@playwright/test';
import { boot, driveAllStates, expectBaselineNotStale, NARROW } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * Every state this lab can render is scanned in both themes at desktop and
 * phone width. See `gate.ts` for why nothing is injected into the page, why no
 * click is allowed to fail silently, why each scan asserts its content first,
 * and why `violations` is not the whole oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(600_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(600_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
  });
}

/**
 * The baseline's third rule: no entry may survive that the lab no longer
 * produces.
 *
 * `nontext-baseline.ts` announces three rules and only two of them were ever
 * live — `expectBaselineNotStale` was exported from `gate.ts` and imported by
 * nothing, so a finding that got FIXED kept its entry forever and the file
 * could only grow. This is that rule's call site.
 *
 * It has to drive BOTH themes before it ratchets, and that is measured rather
 * than chosen. The obvious placement — one call per configuration — was tried
 * first, and the two dark runs failed on `control-boundary|button.btn` while
 * both light runs passed. That entry is the highest-rated of the lab's own
 * findings at 2.23:1, and it clears 3:1 in dark while still failing in light,
 * so dark alone can never see it. The baseline is one flat set with no theme
 * dimension, so only the union of the two themes sees all eight entries.
 * Desktop width is enough: the 380px runs surfaced no entry the 1280px runs
 * missed.
 *
 * This must be verified by running it ALONE — `nonTextSeen` is module state, so
 * under `--workers=1` a wrongly-placed call would free-ride on the tests above
 * and look sound.
 */
test('the non-text baseline holds no entry this lab no longer produces', async ({ page }) => {
  test.setTimeout(600_000);
  for (const theme of ['dark', 'light'] as const) {
    await boot(page, theme);
    await driveAllStates(page, `${theme} / baseline staleness sweep`);
  }
  expectBaselineNotStale();
});
