import config from '../../../config.js';
import logger from '../../utils/logger.js';
import { sanitizeIp } from '../../utils/sanitize.js';
import honeypotStats from '../stats.js';
import { redactCredentialsInText } from '../utils.js';

const SSH_BANNER = 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n';
const MAX_CREDENTIALS_PER_CONNECTION = 20;
const MAX_CREDENTIAL_LENGTH = 256;
const MAX_CLIENT_VERSION_LENGTH = 255;

/**
 * Handle an incoming connection on an SSH honeypot port.
 * Sends a fake SSH banner, captures the client's version string and any
 * credential-like data from the raw byte stream, then records enriched stats.
 */
export function handleSshConnection(socket, port, onThreat) {
  const remoteIp = sanitizeIp(socket.remoteAddress?.replace('::ffff:', ''));
  if (!remoteIp) {
    socket.destroy();
    return;
  }

  const timestamp = new Date().toISOString();
  let clientVersion = '';
  let versionParsed = false;
  let versionBuffer = '';
  const payloadBuffers = [];
  let payloadBytes = 0;
  const credentials = [];

  socket.setTimeout(10_000);
  socket.on('timeout', () => socket.destroy());

  const lifetimeTimer = setTimeout(() => socket.destroy(), config.honeypot.maxConnectionMs);
  socket.on('close', () => clearTimeout(lifetimeTimer));

  // Send the fake SSH banner
  socket.write(SSH_BANNER);

  socket.on('data', chunk => {
    // Bound the chunk to maxPayloadBytes so that version parsing,
    // credential extraction, and payload storage never process or
    // allocate beyond the configured limit.
    const maxBytes = config.honeypot.maxPayloadBytes;
    const bounded = chunk.length > maxBytes ? chunk.subarray(0, maxBytes) : chunk;

    // Accumulate raw payload (bounded).
    // Copy via Buffer.from() so the small slice does not retain
    // a reference to the original (potentially large) Buffer.
    if (payloadBytes < maxBytes) {
      const remaining = maxBytes - payloadBytes;
      const slice = remaining < bounded.length
        ? Buffer.from(bounded.subarray(0, remaining))
        : Buffer.from(bounded);
      payloadBuffers.push(slice);
      payloadBytes += slice.length;
    }

    // Buffer data until a newline is found before parsing SSH identification string
    if (!versionParsed) {
      versionBuffer += bounded.toString('utf8');
      const nlIndex = versionBuffer.indexOf('\n');
      if (nlIndex !== -1) {
        versionParsed = true;
        const line = versionBuffer.slice(0, nlIndex).trim();
        if (line.startsWith('SSH-')) {
          clientVersion = line
            .replace(/[\x00-\x1F\x7F-\x9F]/g, '')
            .slice(0, MAX_CLIENT_VERSION_LENGTH);
        }
      } else if (versionBuffer.length > 512) {
        // Give up if we haven't seen a newline within a reasonable size
        versionParsed = true;
      }
    }

    // Attempt to extract credentials from raw data.
    // Real SSH clients encrypt auth, but many bots/scanners send plaintext
    // or use custom protocols that leak username/password strings.
    if (credentials.length < MAX_CREDENTIALS_PER_CONNECTION) {
      extractCredentials(bounded, credentials);
    }

    if (payloadBytes >= config.honeypot.maxPayloadBytes) {
      socket.destroy();
    }
  });

  socket.on('end', () => finalize());
  socket.on('close', () => finalize());
  socket.on('error', () => socket.destroy());

  let finalized = false;
  function finalize() {
    if (finalized) return;
    finalized = true;

    const rawPayload = payloadBuffers.length > 0 ? Buffer.concat(payloadBuffers).toString('utf8') : '';
    // Strip control chars, then redact plaintext `user=.../pass=...` style
    // guesses so persisted payloads and log previews do not leak credentials.
    const safePayload = redactCredentialsInText(
      rawPayload.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '')
    );

    honeypotStats.record({
      ip: remoteIp,
      port,
      timestamp,
      payload: safePayload,
      banner: SSH_BANNER.trim(),
      clientVersion: clientVersion || null,
      credentials: credentials.length > 0 ? credentials : null,
    });

    const detailParts = [`SSH connection to honeypot port ${port}`];
    if (clientVersion) detailParts.push(`client: ${clientVersion}`);
    if (credentials.length > 0) {
      detailParts.push(`creds attempted: ${credentials.length}`);
    }

    logger.info(`Honeypot SSH hit: ${remoteIp} -> port ${port}`, {
      clientVersion,
      credentials: credentials.length,
      payload: safePayload.slice(0, 100),
    });

    if (onThreat) {
      onThreat({
        rule: 'honeypot',
        severity: 'HIGH',
        ip: remoteIp,
        endpoint: `SSH:${port}`,
        timestamp,
        details: detailParts.join(' — '),
        suggestedAction: 'block',
        source: 'honeypot',
      });
    }
  }
}

/**
 * Sanitize a credential string: strip non-printable characters and truncate.
 */
function sanitizeCredential(value) {
  if (!value) return null;
  const stripped = value.replace(/[\x00-\x1F\x7F-\x9F]/g, '');
  return stripped.slice(0, MAX_CREDENTIAL_LENGTH) || null;
}

/**
 * Scan a raw data chunk for printable strings that look like credential attempts.
 * SSH bots sometimes send plaintext user/pass before or outside the encrypted channel.
 * We also look for common patterns in malformed/custom SSH implementations.
 */
function extractCredentials(chunk, credentials) {
  if (credentials.length >= MAX_CREDENTIALS_PER_CONNECTION) return;

  const text = chunk.toString('utf8');

  // Pattern: lines containing "user" or "pass" keywords (common in bot payloads)
  const userMatch = text.match(/(?:user(?:name)?|login)\s*[=:]\s*(\S+)/i);
  const passMatch = text.match(/(?:pass(?:word)?)\s*[=:]\s*(\S+)/i);
  if (userMatch || passMatch) {
    credentials.push({
      username: sanitizeCredential(userMatch?.[1]),
      password: sanitizeCredential(passMatch?.[1]),
    });
    return;
  }

  // Only attempt null-byte credential extraction when the chunk looks like an
  // SSH_MSG_USERAUTH_REQUEST packet (message type 50 at byte offset 5).
  // Raw handshake packets contain many null bytes and short ASCII algorithm
  // names that would otherwise produce false credential entries.
  if (chunk.length >= 6 && chunk[5] === 50) {
    const nullParts = chunk.toString('latin1').split('\x00').filter(s => {
      const clean = s.replace(/[\x00-\x1F\x7F-\xFF]/g, '').trim();
      return clean.length > 0 && clean.length < 64;
    });
    if (nullParts.length >= 2) {
      credentials.push({
        username: sanitizeCredential(nullParts[0].replace(/[\x00-\x1F\x7F-\xFF]/g, '').trim()),
        password: sanitizeCredential(nullParts[1].replace(/[\x00-\x1F\x7F-\xFF]/g, '').trim()),
      });
    }
  }
}
