import { test, expect } from '@playwright/test';
import { uniqueEmail, testPassword, registerAndVerify, login } from './helpers/auth';
import { deleteAllMessages } from './helpers/mailpit';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { writeFileSync, mkdirSync, existsSync } from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Minimum blob size is 512 bytes — create a test file that meets the requirement
const TEST_FILE_DIR = join(__dirname, '../test-results');
const TEST_FILE_PATH = join(TEST_FILE_DIR, 'test-upload.txt');

test.describe('Blob Storage', () => {
  test.beforeAll(() => {
    if (!existsSync(TEST_FILE_DIR)) mkdirSync(TEST_FILE_DIR, { recursive: true });
    writeFileSync(TEST_FILE_PATH, 'x'.repeat(1024));
  });

  test.beforeEach(async () => {
    await deleteAllMessages();
  });

  test('storage page renders upload form and quota', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/storage');
    await expect(page.getByRole('heading', { name: /storage/i })).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('#blob-file')).toBeVisible();
    await expect(page.locator('#blob-label')).toBeVisible();
  });

  test('quota bar shows zero usage for new user', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/storage');
    await expect(page.getByRole('heading', { name: /storage/i })).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText(/0.*files|0 B/i).first()).toBeVisible({ timeout: 10_000 });
  });

  test('upload file with label', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/storage');
    await expect(page.locator('#blob-file')).toBeVisible({ timeout: 10_000 });

    await page.locator('#blob-file').setInputFiles(TEST_FILE_PATH);
    await page.locator('#blob-label').fill('my-test-file.txt');
    await page.getByRole('button', { name: /upload/i }).click();

    await expect(page.getByText('my-test-file.txt')).toBeVisible({ timeout: 10_000 });
  });

  test('uploaded file shows formatted size', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/storage');
    await expect(page.locator('#blob-file')).toBeVisible({ timeout: 10_000 });

    await page.locator('#blob-file').setInputFiles(TEST_FILE_PATH);
    await page.locator('#blob-label').fill('size-check.txt');
    await page.getByRole('button', { name: /upload/i }).click();

    await expect(page.getByText('size-check.txt')).toBeVisible({ timeout: 10_000 });
    // 1024 bytes → "1 KB" or "1.0 KB" or "1024 B"
    await expect(page.getByText(/1\s*KB|1024\s*B/i).first()).toBeVisible({ timeout: 10_000 });
  });

  test('download button triggers file download', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/storage');
    await expect(page.locator('#blob-file')).toBeVisible({ timeout: 10_000 });

    await page.locator('#blob-file').setInputFiles(TEST_FILE_PATH);
    await page.locator('#blob-label').fill('download-test.txt');
    await page.getByRole('button', { name: /upload/i }).click();
    await expect(page.getByText('download-test.txt')).toBeVisible({ timeout: 10_000 });

    const downloadPromise = page.waitForEvent('download', { timeout: 10_000 });
    await page.getByRole('button', { name: /download/i }).first().click();
    const download = await downloadPromise;
    expect(download).toBeTruthy();
  });

  test('delete file with confirmation modal', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/storage');
    await expect(page.locator('#blob-file')).toBeVisible({ timeout: 10_000 });

    await page.locator('#blob-file').setInputFiles(TEST_FILE_PATH);
    await page.locator('#blob-label').fill('delete-me.txt');
    await page.getByRole('button', { name: /upload/i }).click();
    await expect(page.getByText('delete-me.txt')).toBeVisible({ timeout: 10_000 });

    await page.getByRole('button', { name: /delete/i }).first().click();
    await expect(page.locator('[role="dialog"]')).toBeVisible({ timeout: 5_000 });
    await page.locator('[role="dialog"]').getByRole('button', { name: /delete|confirm/i }).click();

    await expect(page.getByText('delete-me.txt')).not.toBeVisible({ timeout: 10_000 });
  });

  test('cancel delete keeps file in list', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/storage');
    await expect(page.locator('#blob-file')).toBeVisible({ timeout: 10_000 });

    await page.locator('#blob-file').setInputFiles(TEST_FILE_PATH);
    await page.locator('#blob-label').fill('keep-me.txt');
    await page.getByRole('button', { name: /upload/i }).click();
    await expect(page.getByText('keep-me.txt')).toBeVisible({ timeout: 10_000 });

    await page.getByRole('button', { name: /delete/i }).first().click();
    await expect(page.locator('[role="dialog"]')).toBeVisible({ timeout: 5_000 });
    await page.locator('[role="dialog"]').getByRole('button', { name: /cancel/i }).click();

    await expect(page.getByText('keep-me.txt')).toBeVisible();
  });

  test('label input has maxlength 255', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/storage');
    await expect(page.locator('#blob-label')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('#blob-label')).toHaveAttribute('maxlength', '255');
  });

  test('quota bar updates after upload', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/storage');
    await expect(page.locator('#blob-file')).toBeVisible({ timeout: 10_000 });

    await page.locator('#blob-file').setInputFiles(TEST_FILE_PATH);
    await page.getByRole('button', { name: /upload/i }).click();

    // Quota should now show at least 1 file
    await expect(page.getByText(/1.*file/i).first()).toBeVisible({ timeout: 10_000 });
  });

  test('upload without file shows validation', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/storage');
    await expect(page.locator('#blob-file')).toBeVisible({ timeout: 10_000 });

    // file input has required attribute — browser won't submit without it
    const required = await page.locator('#blob-file').getAttribute('required');
    // The file input should prevent submission if empty (HTML5 validation)
    expect(required !== null || required === '').toBeTruthy();
  });
});
