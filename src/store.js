import config from '../config.js';
import logger from './utils/logger.js';

class Store {
  constructor() {
    this.events = new Map();
    this.bannedIps = new Map();
    this.whitelistedIps = new Set();
    this.stats = {
      totalEvents: 0,
      threats: {},
      startedAt: new Date().toISOString(),
    };
    this.cleanupInterval = null;
  }

  startCleanup() {
    this.cleanupInterval = setInterval(() => this.cleanup(), config.storeTtlMs);
  }

  push(key, data) {
    if (!this.events.has(key)) this.events.set(key, []);
    this.events.get(key).push({ ...data, _ts: Date.now() });
  }

  count(key, windowMs) {
    const cutoff = Date.now() - windowMs;
    return (this.events.get(key) || []).filter(e => e._ts > cutoff).length;
  }

  entries(key, windowMs) {
    const cutoff = Date.now() - windowMs;
    return (this.events.get(key) || []).filter(e => e._ts > cutoff);
  }

  uniqueValues(key, field, windowMs) {
    const cutoff = Date.now() - windowMs;
    const items = (this.events.get(key) || []).filter(e => e._ts > cutoff);
    return new Set(items.map(e => e[field]));
  }

  markBanned(ip, jail) {
    this.bannedIps.set(ip, { bannedAt: Date.now(), jail });
  }

  markUnbanned(ip) {
    this.bannedIps.delete(ip);
  }

  getBannedIps() {
    return [...this.bannedIps.entries()].map(([ip, info]) => ({ ip, ...info }));
  }

  wasBanned(ip) {
    return this.bannedIps.has(ip);
  }

  isWhitelisted(ip) {
    return this.whitelistedIps.has(ip);
  }

  whitelist(ip) {
    this.whitelistedIps.add(ip);
    logger.info(`IP whitelisted: ${ip}`);
  }

  incrementThreat(rule, severity) {
    if (!this.stats.threats[rule]) {
      this.stats.threats[rule] = { total: 0, bySeverity: {} };
    }
    this.stats.threats[rule].total++;
    this.stats.threats[rule].bySeverity[severity] =
      (this.stats.threats[rule].bySeverity[severity] || 0) + 1;
    this.stats.totalEvents++;
  }

  getStats() {
    const mem = process.memoryUsage();
    const toMb = bytes => Math.round(bytes / 1024 / 1024 * 10) / 10;
    return {
      ...this.stats,
      uptime: Math.floor(process.uptime()),
      memoryUsage: mem.heapUsed,
      memory: {
        heapUsedMb: toMb(mem.heapUsed),
        heapTotalMb: toMb(mem.heapTotal),
        rssMb: toMb(mem.rss),
      },
      trackedKeys: this.events.size,
      bannedIps: this.bannedIps.size,
      whitelistedIps: this.whitelistedIps.size,
    };
  }

  getDailySummary() {
    return { ...this.stats };
  }

  resetDailyStats() {
    this.stats.threats = {};
    this.stats.totalEvents = 0;
  }

  cleanup() {
    const cutoff = Date.now() - config.storeTtlMs;
    let cleaned = 0;
    for (const [key, entries] of this.events) {
      const filtered = entries.filter(e => e._ts > cutoff);
      if (filtered.length === 0) {
        this.events.delete(key);
        cleaned++;
      } else {
        this.events.set(key, filtered);
      }
    }
    if (cleaned > 0) logger.debug(`Store cleanup: removed ${cleaned} expired keys`);
  }

  stop() {
    if (this.cleanupInterval) clearInterval(this.cleanupInterval);
  }
}

export default new Store();
