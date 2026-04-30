/**
 * Mailpit API client for extracting email OTP codes in E2E tests.
 * Expects Mailpit at https://mail.localhost (or MAILPIT_URL env).
 */

const MAILPIT_URL = process.env.MAILPIT_URL || 'http://mail.localhost';

interface MailpitMessage {
  ID: string;
  MessageID: string;
  From: { Name: string; Address: string };
  To: { Name: string; Address: string }[];
  Subject: string;
  Snippet: string;
  Created: string;
}

interface MailpitSearchResult {
  total: number;
  messages: MailpitMessage[];
}

interface MailpitMessageDetail {
  ID: string;
  Text: string;
  HTML: string;
  Subject: string;
}

export async function getMessages(email: string): Promise<MailpitMessage[]> {
  const res = await fetch(`${MAILPIT_URL}/api/v1/search?query=to:${encodeURIComponent(email)}`, {
    headers: { 'Accept': 'application/json' },
  });
  if (!res.ok) throw new Error(`Mailpit search failed: ${res.status}`);
  const data: MailpitSearchResult = await res.json();
  return data.messages || [];
}

export async function getMessageBody(id: string): Promise<MailpitMessageDetail> {
  const res = await fetch(`${MAILPIT_URL}/api/v1/message/${id}`, {
    headers: { 'Accept': 'application/json' },
  });
  if (!res.ok) throw new Error(`Mailpit message fetch failed: ${res.status}`);
  return res.json();
}

export async function deleteAllMessages(): Promise<void> {
  await fetch(`${MAILPIT_URL}/api/v1/messages`, { method: 'DELETE' });
}

/**
 * Extract a 6-digit OTP code from the latest email to the given address.
 */
export async function getLatestCode(email: string): Promise<string> {
  const messages = await getMessages(email);
  if (messages.length === 0) throw new Error(`No emails found for ${email}`);

  // Sort by Created descending to get the latest
  messages.sort((a, b) => new Date(b.Created).getTime() - new Date(a.Created).getTime());
  const detail = await getMessageBody(messages[0].ID);

  // Look for a 6-digit code in the email text or HTML body
  const body = detail.Text || detail.HTML;
  const match = body.match(/\b(\d{6})\b/);
  if (!match) throw new Error(`No 6-digit code found in email to ${email}`);
  return match[1];
}

/**
 * Wait for a new email to arrive for the given address, then extract the 6-digit code.
 */
export async function waitForCode(email: string, timeoutMs = 15_000): Promise<string> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      return await getLatestCode(email);
    } catch {
      await new Promise(r => setTimeout(r, 500));
    }
  }
  throw new Error(`Timed out waiting for email to ${email}`);
}

/**
 * Wait for a NEW email to arrive after a known count, then extract the code.
 */
export async function waitForNewCode(email: string, previousCount: number, timeoutMs = 20_000): Promise<string> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const messages = await getMessages(email);
    if (messages.length > previousCount) {
      messages.sort((a, b) => new Date(b.Created).getTime() - new Date(a.Created).getTime());
      const detail = await getMessageBody(messages[0].ID);
      const body = detail.Text || detail.HTML;
      const match = body.match(/\b(\d{6})\b/);
      if (match) return match[1];
    }
    await new Promise(r => setTimeout(r, 500));
  }
  throw new Error(`Timed out waiting for new email to ${email} (had ${previousCount} messages)`);
}

/**
 * Extract a password-reset URL from the latest email to the given address.
 */
export async function getResetLink(email: string): Promise<string> {
  const messages = await getMessages(email);
  if (messages.length === 0) throw new Error(`No emails found for ${email}`);
  messages.sort((a, b) => new Date(b.Created).getTime() - new Date(a.Created).getTime());
  const detail = await getMessageBody(messages[0].ID);

  const body = detail.Text || detail.HTML;
  const match = body.match(/https?:\/\/[^\s"<]+reset-password[^\s"<]*/);
  if (!match) throw new Error(`No reset link found in email to ${email}`);
  return match[0];
}

/**
 * Extract an email verification URL from the latest email to the given address.
 */
export async function getVerifyLink(email: string): Promise<string> {
  const messages = await getMessages(email);
  if (messages.length === 0) throw new Error(`No emails found for ${email}`);
  messages.sort((a, b) => new Date(b.Created).getTime() - new Date(a.Created).getTime());
  const detail = await getMessageBody(messages[0].ID);

  const body = detail.Text || detail.HTML;
  const match = body.match(/https?:\/\/[^\s"<]+verify-email[^\s"<]*/);
  if (!match) throw new Error(`No verify link found in email to ${email}`);
  return match[0];
}
