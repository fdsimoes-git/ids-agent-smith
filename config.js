const config = {
  telegram: {
    botToken: process.env.TELEGRAM_BOT_TOKEN || '',
    chatId: process.env.TELEGRAM_CHAT_ID || '',
  },

  anthropic: {
    apiKey: process.env.ANTHROPIC_API_KEY || '',
    model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-20250514',
    decisionModel: process.env.ANTHROPIC_DECISION_MODEL || 'claude-haiku-4-5-20251001',
    maxTokens: 1024,
  },

  autonomousMode: process.env.AUTONOMOUS_MODE === 'true',

  monitoredService: process.env.MONITORED_SERVICE || 'my-app',

  api: {
    port: parseInt(process.env.IDPS_PORT || process.env.IDS_PORT, 10) || 3001,
    bearerToken: process.env.API_BEARER_TOKEN || '',
  },

  allowedCountries: (process.env.ALLOWED_COUNTRIES || 'BR,US')
    .split(',')
    .map(c => c.trim().toUpperCase())
    .filter(Boolean),

  nginxDenyListPath: process.env.NGINX_DENY_LIST_PATH || '/etc/nginx/blocked-ips.conf',

  logs: {
    nginx: process.env.NGINX_LOG_PATH || '/var/log/nginx/access.log',
    auth: process.env.AUTH_LOG_PATH || '/var/log/auth.log',
    ufw: process.env.UFW_LOG_PATH || '/var/log/ufw.log',
    fail2ban: process.env.FAIL2BAN_LOG_PATH || '/var/log/fail2ban.log',
  },

  thresholds: {
    bruteForce: { count: 5, windowSec: 60 },
    portScan: { count: 10, windowSec: 60 },
    httpFlood: { count: 100, windowSec: 60 },
    error4xx: { count: 30, windowSec: 60 },
    error5xx: { count: 3, windowSec: 60 },
    sshAbuse: { count: 3, windowSec: 300 },
  },

  alertCooldownMs: 10 * 60 * 1000, // 10 minutes

  storeTtlMs: 5 * 60 * 1000, // 5 minutes cleanup interval

  dailySummaryHour: 8, // 08:00 AM

  threatHistoryPath: process.env.THREAT_HISTORY_PATH || '/var/lib/idps-agent/threat-history.json',
  aiDecisionLogPath: process.env.AI_DECISION_LOG_PATH || '/var/log/idps-agent/ai-decisions.log',

  memoryAlertMb: (() => {
    const parsed = parseInt(process.env.MEMORY_ALERT_MB, 10);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : 256;
  })(),

  geoip: {
    enabled: process.env.GEOIP_ENABLED !== 'false', // enabled by default
  },

  honeypot: (() => {
    const enabled = process.env.HONEYPOT_ENABLED === 'true';
    const ports = [...new Set(
      (process.env.HONEYPOT_PORTS || '2222,8080,3389,5900')
        .split(',')
        .map(p => parseInt(p.trim(), 10))
        .filter(p => p > 0 && p < 65536)
    )];
    const rawSshPorts = process.env.HONEYPOT_SSH_PORTS;
    const sshPorts = rawSshPorts !== undefined
      ? [...new Set(
        rawSshPorts
          .split(',')
          .map(p => parseInt(p.trim(), 10))
          .filter(p => p > 0 && p < 65536)
      )]
      : (ports.includes(2222) ? [2222] : []);
    if (enabled && ports.length === 0) {
      throw new Error('HONEYPOT_ENABLED=true but HONEYPOT_PORTS has no valid ports');
    }
    const httpEnabled = process.env.HONEYPOT_HTTP_ENABLED === 'true';
    const rawHttpPort = process.env.HONEYPOT_HTTP_PORT;
    const httpPort = rawHttpPort ? parseInt(rawHttpPort, 10) : 8080;
    if (httpEnabled && (Number.isNaN(httpPort) || httpPort < 1 || httpPort > 65535 || !Number.isInteger(httpPort))) {
      throw new Error(`HONEYPOT_HTTP_ENABLED=true but HONEYPOT_HTTP_PORT=${rawHttpPort} is invalid (must be 1-65535)`);
    }
    // When both honeypots are enabled, filter the HTTP port out of TCP ports
    // to prevent bind conflicts (defaults both include 8080)
    if (enabled && httpEnabled && ports.includes(httpPort)) {
      const filtered = ports.filter(p => p !== httpPort);
      if (filtered.length === 0) {
        throw new Error(
          `HONEYPOT_ENABLED=true and HONEYPOT_HTTP_ENABLED=true but all TCP ports overlap ` +
          `with HONEYPOT_HTTP_PORT=${httpPort}. Add non-overlapping ports to HONEYPOT_PORTS`
        );
      }
      ports.length = 0;
      ports.push(...filtered);
    }
    const validSshPorts = sshPorts.filter(p => ports.includes(p));
    const droppedSshPorts = sshPorts.filter(p => !ports.includes(p));
    if (droppedSshPorts.length > 0) {
      if (enabled && rawSshPorts !== undefined) {
        throw new Error(
          `HONEYPOT_ENABLED=true but HONEYPOT_SSH_PORTS contains ports not in HONEYPOT_PORTS ` +
          `(${droppedSshPorts.join(', ')}). Add them to HONEYPOT_PORTS or remove them from HONEYPOT_SSH_PORTS.`
        );
      }
      // eslint-disable-next-line no-console
      console.warn(
        `Warning: HONEYPOT_SSH_PORTS contains ports not in HONEYPOT_PORTS (${droppedSshPorts.join(', ')}); ` +
        `using intersection: [${validSshPorts.join(', ')}]`
      );
    }
    const maxFileMb = (() => {
      const parsed = parseInt(process.env.HONEYPOT_MAX_FILE_MB, 10);
      return Number.isFinite(parsed) && parsed > 0 ? parsed : 50;
    })();
    const archiveEnabled = process.env.HONEYPOT_ARCHIVE_ENABLED !== 'false';
    const archiveNdjson = process.env.HONEYPOT_ARCHIVE_NDJSON === 'true';
    const archiveNdjsonMaxMb = (() => {
      const parsed = parseInt(process.env.HONEYPOT_ARCHIVE_NDJSON_MAX_MB, 10);
      return Number.isFinite(parsed) && parsed > 0 ? parsed : 10;
    })();
    return {
      enabled,
      ports,
      sshPorts: validSshPorts,
      dataPath: process.env.HONEYPOT_DATA_PATH || '/var/log/idps-agent/honeypot.json',
      maxPayloadBytes: 1024,
      maxConnectionMs: 30_000,
      maxRecords: 10_000,
      retentionDays: 7,
      maxFileMb,
      maxArchives: 3,
      archiveEnabled,
      archiveNdjson,
      archiveNdjsonMaxMb,
      http: {
        enabled: httpEnabled,
        port: httpPort,
      },
      dailyDigest: {
        enabled: process.env.HONEYPOT_DAILY_DIGEST === 'true',
        // Support both HONEYPOT_DIGEST_TIME (HH:MM format) and HONEYPOT_DIGEST_HOUR (integer)
        // HONEYPOT_DIGEST_TIME takes precedence when both are set
        ...(() => {
          const timeStr = process.env.HONEYPOT_DIGEST_TIME;
          if (timeStr !== undefined && timeStr !== '') {
            const parts = timeStr.split(':');
            const h = parseInt(parts[0], 10);
            const m = parts.length > 1 ? parseInt(parts[1], 10) : 0;
            if (Number.isNaN(h) || h < 0 || h > 23 ||
                Number.isNaN(m) || m < 0 || m > 59) {
              throw new Error(
                `HONEYPOT_DIGEST_TIME=${timeStr} is invalid (must be HH:MM with hour 0-23 and minute 0-59)`
              );
            }
            return { hour: h, minute: m };
          }
          const hourStr = process.env.HONEYPOT_DIGEST_HOUR;
          if (hourStr !== undefined && hourStr !== '') {
            const parsed = parseInt(hourStr, 10);
            if (Number.isNaN(parsed) || parsed < 0 || parsed > 23) {
              throw new Error(
                `HONEYPOT_DIGEST_HOUR=${hourStr} is invalid (must be an integer 0-23)`
              );
            }
            return { hour: parsed, minute: 0 };
          }
          return { hour: 8, minute: 0 };
        })(),
      },
    };
  })(),
};

export default config;
