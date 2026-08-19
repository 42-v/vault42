// Second line of defence when someone invokes `npx playwright test`
// directly instead of tests/e2e-browser/run.sh. A missing server used
// to become twenty connection errors that looked like product bugs.
//
// Playwright still runs tests after globalSetup exits 0, so a skip-as-
// success cannot live here. Unreachable + REQUIRED=1 fails; unreachable
// without it also fails (honest). The skip-as-success path is run.sh.

const requiredEnv = 'VAULT_E2E_BROWSER_REQUIRED';

export default async function globalSetup(): Promise<void> {
  const url = (process.env.VAULT_URL || 'https://vault.localhost').replace(/\/$/, '');
  const required = process.env[requiredEnv] === '1';
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 3000);
    try {
      const res = await fetch(`${url}/healthz`, { signal: ctrl.signal });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
    } finally {
      clearTimeout(timer);
    }
  } catch (err) {
    const why = err instanceof Error ? err.message : String(err);
    if (required) {
      console.error(
        `FAIL e2e-browser: ${requiredEnv}=1 but no vault42 answered at ${url}: ${why}\n` +
          'This suite needs a deployment and Playwright. Bring one up with scripts/deploy-dev.sh, or\n' +
          `point VAULT_URL at an existing one. Unset ${requiredEnv} only where a skipped run is\n` +
          'genuinely acceptable, which is not a release gate.',
      );
    } else {
      console.error(
        `e2e-browser: vault server not reachable at ${url}: ${why}\n` +
          `Use tests/e2e-browser/run.sh to skip with a named env var (${requiredEnv}).\n` +
          'Invoking Playwright directly against a missing server is a failure, not a pass.',
      );
    }
    throw new Error(`e2e-browser: vault not reachable at ${url}: ${why}`);
  }
}
