/**
 * Mask a password for display: show up to the first 2 characters followed by
 * asterisks.  Passwords of 2 or fewer characters are shown in full.
 */
export function maskPassword(password) {
  if (!password || password === '—') return password || '?';
  if (password.length <= 2) return password;
  return password.slice(0, 2) + '*'.repeat(Math.min(password.length - 2, 6));
}
