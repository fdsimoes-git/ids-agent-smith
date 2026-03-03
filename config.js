const config = {
  telegram: {
    botToken: process.env.TELEGRAM_BOT_TOKEN || '',
    chatId: process.env.TELEGRAM_CHAT_ID || '',
  },

  anthropic: {
    apiKey: process.env.ANTHROPIC_API_KEY || '',
    model: 'claude-sonnet-4-20250514',
    maxTokens: 1024,
  },

  autonomousMode: process.env.AUTONOMOUS_MODE === 'true',

  monitoredService: process.env.MONITORED_SERVICE || 'my-app',

  api: {
    port: parseInt(process.env.IDS_PORT, 10) || 3001,
    bearerToken: process.env.API_BEARER_TOKEN || '',
  },

  allowedCountries: (process.env.ALLOWED_COUNTRIES || 'BR,US')
    .split(',')
    .map(c => c.trim().toUpperCase())
    .filter(Boolean),

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

  threatHistoryPath: process.env.THREAT_HISTORY_PATH || '/var/log/ids-agent/threat-history.json',
  aiDecisionLogPath: process.env.AI_DECISION_LOG_PATH || '/var/log/ids-agent/ai-decisions.log',
};

export default config;
