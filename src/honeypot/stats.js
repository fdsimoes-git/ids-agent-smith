import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import config from '../../config.js';
import logger from '../utils/logger.js';
import { lookupIp } from '../utils/geoip.js';

class HoneypotStats {
  constructor() {
    this.connections = [];
    this.dirty = false;
    this.saveTimer = null;
    this.isSaving = false;
    this.savePromise = null;
  }

  async load() {
    try {
      const raw = await readFile(config.honeypot.dataPath, 'utf8');
      const data = JSON.parse(raw);
      if (Array.isArray(data.connections)) {
        this.connections = data.connections;
        this.trimOld();
        if (this.connections.length > config.honeypot.maxRecords) {
          this.connections = this.connections.slice(-config.honeypot.maxRecords);
          this.dirty = true;
        }
        logger.info(`Honeypot stats loaded: ${this.connections.length} records`);
      }
    } catch (err) {
      if (err.code !== 'ENOENT') {
        logger.warn('Failed to load honeypot stats', { error: err.message });
      }
    }
  }

  startAutoSave() {
    if (this.saveTimer) clearInterval(this.saveTimer);
    this.saveTimer = setInterval(() => {
      this.trimOld();
      if (this.dirty && !this.isSaving) this.save();
    }, 60_000);
  }

  record(event) {
    if (this.connections.length >= config.honeypot.maxRecords) {
      this.connections.splice(0, Math.ceil(config.honeypot.maxRecords * 0.1));
    }

    const entry = {
      ip: event.ip,
      port: event.port,
      timestamp: event.timestamp,
      payload: event.payload || '',
    };
    if (event.username) entry.username = event.username;
    if (event.passwordHash) entry.passwordHash = event.passwordHash;

    // Push immediately so max-records trimming stays accurate during bursts
    this.connections.push(entry);
    this.dirty = true;

    // Enrich with geo-IP data in the background (best-effort)
    lookupIp(event.ip).then(geo => {
      if (geo) {
        entry.geo = geo;
        this.dirty = true;
      }
    }).catch(() => {
      // geo enrichment is best-effort
    });
  }

  trimOld() {
    const cutoff = Date.now() - config.honeypot.retentionDays * 86400_000;
    const before = this.connections.length;
    this.connections = this.connections.filter(c => new Date(c.timestamp).getTime() > cutoff);
    if (this.connections.length < before) {
      this.dirty = true;
    }
  }

  getAll() {
    return this.connections;
  }

  getSummary() {
    const now = Date.now();
    const last24h = now - 86400_000;
    const recent = this.connections.filter(c => new Date(c.timestamp).getTime() > last24h);

    const byIp = Object.create(null);
    const byPort = Object.create(null);
    const byHour = Object.create(null);
    const byCountry = Object.create(null);
    const ipGeo = Object.create(null);

    for (const conn of this.connections) {
      byIp[conn.ip] = (byIp[conn.ip] || 0) + 1;
      byPort[conn.port] = (byPort[conn.port] || 0) + 1;

      if (conn.geo?.countryCode && /^[A-Z]{2}$/.test(conn.geo.countryCode)) {
        const key = conn.geo.countryCode;
        byCountry[key] = (byCountry[key] || { country: conn.geo.country, countryCode: key, count: 0 });
        byCountry[key].count++;
        // Keep latest geo per IP for topIps enrichment
        ipGeo[conn.ip] = conn.geo;
      }
    }

    for (const conn of recent) {
      const hour = new Date(conn.timestamp).getHours();
      const key = String(hour).padStart(2, '0') + ':00';
      byHour[key] = (byHour[key] || 0) + 1;
    }

    const topIps = Object.entries(byIp)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([ip, count]) => {
        const entry = { ip, count };
        if (ipGeo[ip]) {
          entry.geo = ipGeo[ip];
        }
        return entry;
      });

    const topPorts = Object.entries(byPort)
      .sort((a, b) => b[1] - a[1])
      .map(([port, count]) => ({ port: Number(port), count }));

    const hourly = Object.entries(byHour)
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([hour, count]) => ({ hour, count }));

    const topCountries = Object.values(byCountry)
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    const recentPayloads = this.connections
      .filter(c => c.payload)
      .slice(-10)
      .reverse()
      .map(c => ({ ip: c.ip, port: c.port, timestamp: c.timestamp, payload: c.payload, geo: c.geo || null }));

    return {
      totalConnections: this.connections.length,
      connectionsLast24h: recent.length,
      uniqueIps: Object.keys(byIp).length,
      topIps,
      topPorts,
      topCountries,
      hourlyLast24h: hourly,
      recentPayloads,
    };
  }

  async save() {
    if (this.isSaving) return this.savePromise;
    this.isSaving = true;
    this.savePromise = (async () => {
      try {
        const dir = dirname(config.honeypot.dataPath);
        await mkdir(dir, { recursive: true }).catch(() => {});
        await writeFile(
          config.honeypot.dataPath,
          JSON.stringify({ connections: this.connections }, null, 2),
          'utf8'
        );
        this.dirty = false;
      } catch (err) {
        logger.error('Failed to save honeypot stats', { error: err.message });
      } finally {
        this.isSaving = false;
        this.savePromise = null;
      }
    })();
    return this.savePromise;
  }

  async stop() {
    if (this.saveTimer) clearInterval(this.saveTimer);
    if (this.savePromise) await this.savePromise;
    if (this.dirty) await this.save();
  }
}

export default new HoneypotStats();
