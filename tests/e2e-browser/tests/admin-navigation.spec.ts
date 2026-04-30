import { test, expect } from '@playwright/test';
import { getAdminToken, authenticateAdminPage, gotoAdminPage } from './helpers/admin';

const ADMIN_PASSWORD = process.env.ADMIN_FIRST_PASSWORD || '';

test.describe('Admin Navigation & Layout', () => {
  test.skip(!ADMIN_PASSWORD, 'ADMIN_FIRST_PASSWORD env var required');

  let adminToken: string;

  test.beforeAll(async ({ request }) => {
    adminToken = await getAdminToken(request);
  });

  // ----- Sidebar Navigation -----

  test('sidebar shows all nav links', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/');

    const sidebar = page.locator('#sidebar');
    await expect(sidebar).toBeVisible({ timeout: 10_000 });

    await expect(sidebar.getByText('Dashboard')).toBeVisible();
    await expect(sidebar.getByText('Users')).toBeVisible();
    await expect(sidebar.getByText('Keys')).toBeVisible();
    await expect(sidebar.getByText('Sessions')).toBeVisible();
    await expect(sidebar.getByText('Audit')).toBeVisible();
    await expect(sidebar.getByText('Clients')).toBeVisible();
    await expect(sidebar.getByText('Admins')).toBeVisible();
    await expect(sidebar.getByText('Config')).toBeVisible();
  });

  test('sidebar shows admin username and role', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/');

    const sidebar = page.locator('#sidebar');
    await expect(sidebar).toBeVisible({ timeout: 10_000 });

    // Admin info in footer
    await expect(sidebar.getByText('admin')).toBeVisible();
    await expect(sidebar.locator('.role-badge')).toBeVisible();
  });

  test('sidebar logo shows VAULTADMIN', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/');

    await expect(page.locator('.logo')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('.logo').getByText('VAULT')).toBeVisible();
    await expect(page.locator('.logo .accent')).toContainText('ADMIN');
  });

  test('nav links navigate to correct pages', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);

    const pages = [
      { name: 'Users', url: '/admin/ui/users', heading: 'Users' },
      { name: 'Keys', url: '/admin/ui/keys', heading: 'Signing Keys' },
      { name: 'Sessions', url: '/admin/ui/sessions', heading: 'Admin Sessions' },
      { name: 'Audit', url: '/admin/ui/audit', heading: 'Audit Log' },
      { name: 'Clients', url: '/admin/ui/clients', heading: 'Service Clients' },
      { name: 'Admins', url: '/admin/ui/admins', heading: 'Admin Accounts' },
      { name: 'Config', url: '/admin/ui/config', heading: 'Configuration' },
    ];

    for (const p of pages) {
      await gotoAdminPage(page, p.url);
      await expect(page.getByText(p.heading).first()).toBeVisible({ timeout: 10_000 });
    }
  });

  test('active page is highlighted in sidebar', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);

    // Navigate to Users page
    await gotoAdminPage(page, '/admin/ui/users');
    const activeLink = page.locator('a.nav-link.active');
    await expect(activeLink).toContainText('Users');

    // Navigate to Audit page
    await gotoAdminPage(page, '/admin/ui/audit');
    const auditLink = page.locator('a.nav-link.active');
    await expect(auditLink).toContainText('Audit');
  });

  // ----- Logout -----

  test('logout button is visible in sidebar', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/');

    await expect(page.locator('[data-action="logout"]')).toBeVisible({ timeout: 10_000 });
  });

  test('logout clears session and redirects to login', async ({ page, request }) => {
    // Get a separate token for this test (avoid invalidating shared token)
    const logoutToken = await getAdminToken(request);
    await authenticateAdminPage(page, logoutToken);
    await gotoAdminPage(page, '/admin/');

    await page.locator('[data-action="logout"]').click();

    // Should redirect to login page
    await expect(page.locator('#loginForm')).toBeVisible({ timeout: 10_000 });
  });

  // ----- Auth Enforcement -----

  test('unauthenticated access to dashboard returns 401', async ({ page }) => {
    // Navigate without auth headers
    const response = await page.goto('/admin/');
    // Should get 401 (SessionAuth rejects missing Authorization header)
    expect(response?.status()).toBe(401);
  });

  test('unauthenticated access to API returns 401', async ({ page }) => {
    const response = await page.goto('/admin/keys');
    expect(response?.status()).toBe(401);
  });

  test('login page is accessible without authentication', async ({ page }) => {
    const response = await page.goto('/admin/login');
    expect(response?.status()).toBe(200);
    await expect(page.locator('#loginForm')).toBeVisible();
  });

  test('static assets are accessible without authentication', async ({ page }) => {
    const cssResponse = await page.goto('/admin/static/style.css');
    expect(cssResponse?.status()).toBe(200);

    const jsResponse = await page.goto('/admin/static/admin.js');
    expect(jsResponse?.status()).toBe(200);
  });

  // ----- Security Headers -----

  test('login page returns security headers', async ({ page }) => {
    const response = await page.goto('/admin/login');
    const headers = response?.headers() || {};

    expect(headers['x-content-type-options']).toBe('nosniff');
    expect(headers['x-frame-options']).toBe('DENY');
    expect(headers['cache-control']).toContain('no-store');
    expect(headers['content-security-policy']).toBeTruthy();
    expect(headers['strict-transport-security']).toBeTruthy();
  });

  // ----- Page Titles -----

  test('each page has correct title suffix', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);

    await gotoAdminPage(page, '/admin/');
    expect(await page.title()).toContain('Vault Admin');

    await gotoAdminPage(page, '/admin/ui/keys');
    expect(await page.title()).toContain('Signing Keys');

    await gotoAdminPage(page, '/admin/ui/users');
    expect(await page.title()).toContain('Users');
  });

  // ----- Toast Notifications -----

  test('toast container is present on authenticated pages', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/');

    await expect(page.locator('#toastContainer')).toBeVisible({ timeout: 10_000 });
  });

  // ----- Modal -----

  test('modal overlay is hidden by default', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/');

    await expect(page.locator('#modalOverlay')).not.toBeVisible();
  });

  test('modal has Cancel and Confirm buttons', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/');

    // Modal exists in DOM but is hidden
    await expect(page.locator('#modalCancel')).toBeAttached();
    await expect(page.locator('#modalConfirm')).toBeAttached();
  });

  // ----- Sidebar Toggle (Mobile) -----

  test('sidebar toggle button exists', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/');

    await expect(page.locator('#sidebarToggle')).toBeVisible({ timeout: 10_000 });
  });
});
