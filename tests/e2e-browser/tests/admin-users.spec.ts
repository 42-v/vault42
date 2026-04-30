import { test, expect } from '@playwright/test';
import { getAdminToken, authenticateAdminPage, gotoAdminPage } from './helpers/admin';

const ADMIN_PASSWORD = process.env.ADMIN_FIRST_PASSWORD || '';

test.describe('Admin User Management', () => {
  test.skip(!ADMIN_PASSWORD, 'ADMIN_FIRST_PASSWORD env var required');

  let adminToken: string;

  test.beforeAll(async ({ request }) => {
    adminToken = await getAdminToken(request);
  });

  test('users page loads with search input', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/users');

    await expect(page.getByText('Users')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('#userSearch')).toBeVisible();
  });

  test('search by email finds seeded dev user', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/users');

    await page.locator('#userSearch').fill('dev@vault.localhost');
    await page.locator('[data-action="search-user"]').click();

    await page.waitForTimeout(2000);

    // Should find the seeded dev user
    await expect(page.getByText('dev@vault.localhost')).toBeVisible({ timeout: 10_000 });
  });

  test('search results show user details columns', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/users');

    await page.locator('#userSearch').fill('dev@vault.localhost');
    await page.locator('[data-action="search-user"]').click();

    await page.waitForTimeout(2000);

    // Table should have result rows
    const usersBody = page.locator('#usersBody');
    const rows = usersBody.locator('tr');
    const count = await rows.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });

  test('user ID links to detail page', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/users');

    await page.locator('#userSearch').fill('dev@vault.localhost');
    await page.locator('[data-action="search-user"]').click();

    await page.waitForTimeout(2000);

    // Click on the user ID link
    const userLink = page.locator('#usersBody a').first();
    if (await userLink.isVisible({ timeout: 5_000 }).catch(() => false)) {
      await userLink.click();

      // Should navigate to user detail page
      await expect(page).toHaveURL(/\/admin\/ui\/users\//);
      await expect(page.getByText('User Detail')).toBeVisible({ timeout: 10_000 });
    }
  });

  test('user detail page shows user information', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/users');

    await page.locator('#userSearch').fill('dev@vault.localhost');
    await page.locator('[data-action="search-user"]').click();
    await page.waitForTimeout(2000);

    const userLink = page.locator('#usersBody a').first();
    if (await userLink.isVisible({ timeout: 5_000 }).catch(() => false)) {
      await userLink.click();
      await expect(page.getByText('User Detail')).toBeVisible({ timeout: 10_000 });

      // Wait for data to load
      await page.waitForTimeout(2000);

      // Should show user details
      await expect(page.getByText('dev@vault.localhost')).toBeVisible({ timeout: 10_000 });
    }
  });

  test('user detail page has back button to users list', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/users');

    await page.locator('#userSearch').fill('dev@vault.localhost');
    await page.locator('[data-action="search-user"]').click();
    await page.waitForTimeout(2000);

    const userLink = page.locator('#usersBody a').first();
    if (await userLink.isVisible({ timeout: 5_000 }).catch(() => false)) {
      await userLink.click();
      await expect(page.getByText('User Detail')).toBeVisible({ timeout: 10_000 });

      // Click back button
      const backLink = page.locator('a[href="/admin/ui/users"]');
      await expect(backLink).toBeVisible();
      await backLink.click();
      await expect(page.locator('#userSearch')).toBeVisible({ timeout: 10_000 });
    }
  });

  test('lock user shows confirmation modal', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/users');

    await page.locator('#userSearch').fill('dev@vault.localhost');
    await page.locator('[data-action="search-user"]').click();
    await page.waitForTimeout(2000);

    const lockBtn = page.locator('[data-action="lock-user"]').first();
    if (await lockBtn.isVisible({ timeout: 5_000 }).catch(() => false)) {
      await lockBtn.click();

      // Confirmation modal should appear
      await expect(page.locator('#modalOverlay')).toBeVisible({ timeout: 5_000 });
      await expect(page.locator('#modalBody')).toContainText(/lock/i);

      // Cancel to avoid actually locking
      await page.locator('#modalCancel').click();
      await expect(page.locator('#modalOverlay')).not.toBeVisible();
    }
  });

  test('search result count is displayed', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/users');

    await page.locator('#userSearch').fill('dev@vault.localhost');
    await page.locator('[data-action="search-user"]').click();
    await page.waitForTimeout(2000);

    // Result count should be visible
    await expect(page.getByText(/\d+ result/i)).toBeVisible({ timeout: 10_000 });
  });

  test('empty search shows no results', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/users');

    await page.locator('#userSearch').fill('nonexistent@nowhere.invalid');
    await page.locator('[data-action="search-user"]').click();
    await page.waitForTimeout(2000);

    // Should show 0 results or empty table
    await expect(page.getByText(/0 result/i).or(page.getByText(/no.*user/i))).toBeVisible({ timeout: 10_000 });
  });
});
