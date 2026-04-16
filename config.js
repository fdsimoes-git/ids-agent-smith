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
    return {
      enabled,
      ports,
      dataPath: process.env.HONEYPOT_DATA_PATH || '/var/log/idps-agent/honeypot.json',
      maxPayloadBytes: 1024,
      maxConnectionMs: 30_000,
      maxRecords: 10_000,
      retentionDays: 7,
      http: {
        enabled: httpEnabled,
        port: httpPort,
      },
      dailyDigest: {
        enabled: process.env.HONEYPOT_DAILY_DIGEST === 'true',
        hour: parseInt(process.env.HONEYPOT_DIGEST_HOUR, 10) || 8,
      },
    };
  })(),
};

export default config;
