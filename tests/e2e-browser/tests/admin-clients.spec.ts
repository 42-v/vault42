import { test, expect } from '@playwright/test';
import { getAdminToken, authenticateAdminPage, gotoAdminPage } from './helpers/admin';

const ADMIN_PASSWORD = process.env.ADMIN_FIRST_PASSWORD || '';

test.describe('Admin Client Management', () => {
  test.skip(!ADMIN_PASSWORD, 'ADMIN_FIRST_PASSWORD env var required');

  let adminToken: string;

  test.beforeAll(async ({ request }) => {
    adminToken = await getAdminToken(request);
  });

  test('clients page loads with table', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/clients');

    await expect(page.getByText('Service Clients')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('#clientsBody')).toBeVisible();
  });

  test('clients table shows seeded clients', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/clients');

    await page.waitForTimeout(2000);

    // Seeded clients: "frontend" and "backend"
    await expect(page.getByText('frontend').first()).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText('backend').first()).toBeVisible({ timeout: 10_000 });
  });

  test('active client shows active badge', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/clients');

    await page.waitForTimeout(2000);

    await expect(page.locator('#clientsBody .status-active').first()).toBeVisible({ timeout: 10_000 });
  });

  test('create client form toggles on button click', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/clients');

    await expect(page.getByText('Service Clients')).toBeVisible({ timeout: 10_000 });

    // Create form should be hidden initially
    const form = page.locator('#createClientForm');
    await expect(form).not.toBeVisible();

    // Click "Create Client" button
    await page.locator('[data-action="show-create-client"]').click();
    await expect(form).toBeVisible();

    // Cancel hides the form
    await page.locator('[data-action="hide-create-client"]').click();
    await expect(form).not.toBeVisible();
  });

  test('create new client and verify it appears', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/clients');

    await page.waitForTimeout(2000);

    const clientName = `e2e-test-${Date.now()}`;

    // Open create form
    await page.locator('[data-action="show-create-client"]').click();
    await expect(page.locator('#createClientForm')).toBeVisible();

    // Fill in client details
    await page.locator('#createClientForm input[type="text"]').first().fill(clientName);

    // Click create
    await page.locator('[data-action="create-client"]').click();

    // Should show success toast and client in table
    await page.waitForTimeout(3000);

    // New client should appear in table
    await expect(page.getByText(clientName)).toBeVisible({ timeout: 10_000 });
  });

  test('rotate client secret shows confirmation', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/clients');

    await page.waitForTimeout(2000);

    const rotateBtn = page.locator('[data-action="rotate-client"]').first();
    if (await rotateBtn.isVisible({ timeout: 5_000 }).catch(() => false)) {
      await rotateBtn.click();

      // Confirmation modal
      await expect(page.locator('#modalOverlay')).toBeVisible({ timeout: 5_000 });
      await expect(page.locator('#modalBody')).toContainText(/rotate|secret/i);

      // Cancel to avoid mutation
      await page.locator('#modalCancel').click();
    }
  });

  test('revoke client shows confirmation', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/clients');

    await page.waitForTimeout(2000);

    const revokeBtn = page.locator('[data-action="revoke-client"]').first();
    if (await revokeBtn.isVisible({ timeout: 5_000 }).catch(() => false)) {
      await revokeBtn.click();

      // Confirmation modal
      await expect(page.locator('#modalOverlay')).toBeVisible({ timeout: 5_000 });
      await expect(page.locator('#modalBody')).toContainText(/revoke|undo/i);

      // Cancel
      await page.locator('#modalCancel').click();
    }
  });

  test('refresh button reloads client list', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/clients');

    await page.waitForTimeout(2000);

    const refreshBtn = page.locator('[data-action="refresh-clients"]');
    await expect(refreshBtn).toBeVisible({ timeout: 5_000 });
    await refreshBtn.click();

    await page.waitForTimeout(2000);

    const rows = await page.locator('#clientsBody tr').count();
    expect(rows).toBeGreaterThanOrEqual(1);
  });

  test('client creation form auto-focuses name input', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/clients');

    await expect(page.getByText('Service Clients')).toBeVisible({ timeout: 10_000 });

    await page.locator('[data-action="show-create-client"]').click();
    await expect(page.locator('#createClientForm')).toBeVisible();

    // First input in form should be focused
    const firstInput = page.locator('#createClientForm input[type="text"]').first();
    await expect(firstInput).toBeFocused({ timeout: 3_000 });
  });
});
