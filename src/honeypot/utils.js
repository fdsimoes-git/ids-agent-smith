/**
 * Mask a password for display: show up to the first 2 characters followed by
 * up to 6 asterisks (the asterisk count is capped at 6 to avoid leaking the
 * original length). Passwords of 2 or fewer characters are shown in full.
 */
export function maskPassword(password) {
  if (!password || password === '—') return password || '?';
  if (password.length <= 2) return password;
  return password.slice(0, 2) + '*'.repeat(Math.min(password.length - 2, 6));
}

/**
 * Redact credential-like substrings (e.g. `user=foo pass=bar`, `login: x`,
 * `password:y`) from a payload string before it is persisted or logged.
 * The key is preserved and the value replaced with `[REDACTED]` so that the
 * presence of a credential guess is visible without leaking the value.
 */
export function redactCredentialsInText(text) {
  if (!text) return text;
  return text.replace(
    /((?:user(?:name)?|login|pass(?:word)?)\s*[=:]\s*)(\S+)/gi,
    '$1[REDACTED]'
  );
}
