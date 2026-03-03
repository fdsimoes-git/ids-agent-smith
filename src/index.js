import config from '../config.js';
import logger from './utils/logger.js';
import { LogTailer, JournalTailer } from './utils/log-tailer.js';
import { CooldownManager } from './utils/cooldown.js';
import store from './store.js';
import memory from './ai/memory.js';
import { parseNginxLine } from './parsers/nginx.js';
import { parseAuthLine } from './parsers/auth.js';
import { parseUfwLine } from './parsers/ufw.js';
import { parseFail2banLine } from './parsers/fail2ban.js';
import { parseJournalLine } from './parsers/journal.js';
import { runDetectors } from './detectors/index.js';
import { sendAlert, sendAIAnalysis, sendActionTaken, sendMessage } from './alerters/telegram.js';
import { scheduleDailySummary, stopDailySummary } from './alerters/daily-summary.js';
import { analyzeThreat, generateWeeklyReport } from './ai/analyzer.js';
import { executeAction } from './ai/actions.js';
import { startApiServer, stopApiServer } from './api/server.js';
import { startBot, stopBot } from './bot/commands.js';

const cooldown = new CooldownManager(config.alertCooldownMs);
const tailers = [];
let weeklyTimer = null;
let cleanupTimer = null;

// --- Threat handling pipeline ---

async function handleThreat(threat) {
  if (threat.ip && store.isWhitelisted(threat.ip)) return;
  if (!cooldown.shouldAlert(threat.ip || 'global', threat.rule)) return;

  store.incrementThreat(threat.rule, threat.severity);
  memory.addEvent(threat);

  await sendAlert(threat);

  // AI analysis for HIGH / CRITICAL threats
  if (threat.severity === 'HIGH' || threat.severity === 'CRITICAL') {
    const history = memory.getLast24h();
    const analysis = await analyzeThreat(threat, history);

    if (analysis) {
      await sendAIAnalysis(threat, analysis);

      if (config.autonomousMode && analysis.action === 'block' && analysis.confidence >= 70) {
        await executeAction('block', threat.ip, analysis);
        await sendActionTaken(threat.ip, analysis);
      } else if (!config.autonomousMode && analysis.action === 'block') {
        await sendMessage(
          `\u26A0\uFE0F AI recommends <b>blocking</b> <code>${threat.ip}</code> ` +
          `(confidence: ${analysis.confidence}%)\n` +
          `Reply: /block_ip ${threat.ip}`
        );
      }
    }
  }
}

function processLine(source, parser, raw) {
  try {
    const event = parser(raw);
    if (!event) return;

    const threats = runDetectors(event, store);
    for (const threat of threats) {
      handleThreat(threat).catch(err => {
        logger.error('Threat handler error', { rule: threat.rule, error: err.message });
      });
    }
  } catch (err) {
    logger.error(`Error processing ${source} log line`, { error: err.message });
  }
}

// --- Weekly AI report ---

function scheduleWeeklyReport() {
  weeklyTimer = setInterval(async () => {
    const now = new Date();
    // Monday at the configured summary hour
    if (now.getDay() === 1 && now.getHours() === config.dailySummaryHour && now.getMinutes() === 0) {
      logger.info('Generating weekly AI threat report');
      try {
        const history = memory.getLastWeek();
        if (history.length === 0) return;
        const report = await generateWeeklyReport(history);
        if (report) {
          await sendMessage(
            `\u{1F4CB} <b>Weekly AI Threat Report</b>\n\n` +
            report
          );
        }
      } catch (err) {
        logger.error('Weekly report failed', { error: err.message });
      }
    }
  }, 60_000);
}

// --- Graceful shutdown ---

async function shutdown(signal) {
  logger.info(`Received ${signal}, shutting down`);

  if (cleanupTimer) clearInterval(cleanupTimer);
  if (weeklyTimer) clearInterval(weeklyTimer);
  stopDailySummary();
  stopBot();

  for (const tailer of tailers) {
    try {
      await tailer.stop();
    } catch {
      // best effort
    }
  }

  await stopApiServer();
  store.stop();
  await memory.stop();

  await sendMessage('\u{1F534} <b>IDS Agent Offline</b>').catch(() => {});
  logger.info('Shutdown complete');
  process.exit(0);
}

// --- Main startup ---

async function main() {
  logger.info('IDS Agent starting', {
    autonomousMode: config.autonomousMode,
    monitoredService: config.monitoredService,
    allowedCountries: config.allowedCountries,
    port: config.api.port,
  });

  await memory.load();
  store.startCleanup();

  // File tailers
  const nginxTailer = new LogTailer(config.logs.nginx, line => processLine('nginx', parseNginxLine, line));
  const authTailer = new LogTailer(config.logs.auth, line => processLine('auth', parseAuthLine, line));
  const ufwTailer = new LogTailer(config.logs.ufw, line => processLine('ufw', parseUfwLine, line));
  const f2bTailer = new LogTailer(config.logs.fail2ban, line => processLine('fail2ban', parseFail2banLine, line));
  const journalTailer = new JournalTailer(config.monitoredService, line => processLine('journal', parseJournalLine, line));

  tailers.push(nginxTailer, authTailer, ufwTailer, f2bTailer, journalTailer);

  await Promise.all([
    nginxTailer.start(),
    authTailer.start(),
    ufwTailer.start(),
    f2bTailer.start(),
  ]);

  journalTailer.start();

  // HTTP API
  startApiServer(store);

  // Telegram bot commands
  startBot(store, memory);

  // Scheduled reports
  scheduleDailySummary(store, memory);
  scheduleWeeklyReport();

  // Periodic cleanup
  cleanupTimer = setInterval(() => {
    store.cleanup();
    cooldown.cleanup();
  }, config.storeTtlMs);

  // Startup notification
  await sendMessage(
    `\u{1F6E1}\uFE0F <b>IDS Agent Online</b>\n\n` +
    `Autonomous mode: <b>${config.autonomousMode ? 'ON' : 'OFF'}</b>\n` +
    `Monitoring: ${config.monitoredService}\n` +
    `API port: ${config.api.port}`
  );

  logger.info('IDS Agent fully operational');

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main().catch(err => {
  logger.error('Fatal startup error', { error: err.message, stack: err.stack });
  process.exit(1);
});
