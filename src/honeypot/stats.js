import { readFile, writeFile, mkdir, stat, readdir, unlink } from 'node:fs/promises';
import { createReadStream, createWriteStream } from 'node:fs';
import { createGzip } from 'node:zlib';
import { pipeline } from 'node:stream/promises';
import { basename, dirname, join } from 'node:path';
import { createHash } from 'node:crypto';
import config from '../../config.js';
import logger from '../utils/logger.js';
import { lookupIp } from '../utils/geoip.js';
import { maskPassword } from './utils.js';

function hashPassword(password) {
  if (!password) return null;
  return createHash('sha256').update(password).digest('hex').slice(0, 16);
}

const ROTATE_COOLDOWN_MS = 60 * 60 * 1000;

const HTTP_METHOD_PREFIX = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT) /;

function inferSource(conn) {
  if (conn.source === 'ssh' || conn.source === 'http' || conn.source === 'tcp') {
    return conn.source;
  }
  if (conn.banner || conn.clientVersion || conn.credentials) return 'ssh';
  if (typeof conn.payload === 'string' && HTTP_METHOD_PREFIX.test(conn.payload)) return 'http';
  return 'tcp';
}

class HoneypotStats {
  constructor() {
    this.connections = [];
    this.dirty = false;
    this.saveTimer = null;
    this.isSaving = false;
    this.savePromise = null;
    this.lastRotateMs = 0;
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
    if (event.source) entry.source = event.source;

    // Enriched SSH fields (only present for SSH honeypot ports)
    if (event.banner) entry.banner = event.banner;
    if (event.clientVersion) entry.clientVersion = event.clientVersion;
    if (event.credentials) {
      entry.credentials = event.credentials.map(c => ({
        username: c.username,
        password: maskPassword(c.password),
        passwordHash: hashPassword(c.password),
      }));
    }

    // Push immediately so max-records trimming stays accurate during bursts
    this.connections.push(entry);
    this.dirty = true;

    // Enrich with geo-IP data in the background (best-effort)
    if (!config.geoip?.enabled) return;
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
    const ipPorts = Object.create(null);
    const ipPayloads = Object.create(null);
    const vectorBreakdown = { ssh: 0, http: 0, tcp: 0 };
    const isoAlpha2 = /^[A-Z]{2}$/;

    // Rolling 24h timeline: 24 consecutive UTC-hour buckets ending at the
    // current hour. Keyed by bucket-start epoch ms so ordering is chronological
    // even across midnight (fixes out-of-order hour-of-day aggregation).
    const HOUR_MS = 3_600_000;
    const nowHourStart = Math.floor(now / HOUR_MS) * HOUR_MS;
    const firstHourStart = nowHourStart - 23 * HOUR_MS;

    for (const conn of recent) {
      byIp[conn.ip] = (byIp[conn.ip] || 0) + 1;
      byPort[conn.port] = (byPort[conn.port] || 0) + 1;

      const source = inferSource(conn);
      if (source in vectorBreakdown) vectorBreakdown[source]++;

      // Track ports and latest payloads per IP for expandable detail rows.
      // Iteration is oldest→newest, so appending and trimming from the front
      // keeps the 3 most recent payloads per IP.
      if (!ipPorts[conn.ip]) ipPorts[conn.ip] = Object.create(null);
      ipPorts[conn.ip][conn.port] = (ipPorts[conn.ip][conn.port] || 0) + 1;
      if (conn.payload) {
        const list = ipPayloads[conn.ip] || (ipPayloads[conn.ip] = []);
        list.push(conn.payload);
        if (list.length > 3) list.shift();
      }

      const rawCode = conn.geo?.countryCode;
      if (typeof rawCode === 'string' && isoAlpha2.test(rawCode)) {
        const code = rawCode;
        const country = typeof conn.geo.country === 'string' ? conn.geo.country.trim() : '';
        if (!byCountry[code]) {
          byCountry[code] = { country: country || code, countryCode: code, count: 0 };
        } else if ((!byCountry[code].country || byCountry[code].country === code) && country) {
          byCountry[code].country = country;
        }
        byCountry[code].count++;
        // Keep latest geo per IP for topIps enrichment
        ipGeo[conn.ip] = conn.geo;
      }

      const connMs = new Date(conn.timestamp).getTime();
      const bucketStart = Math.floor(connMs / HOUR_MS) * HOUR_MS;
      if (bucketStart >= firstHourStart && bucketStart <= nowHourStart) {
        byHour[bucketStart] = (byHour[bucketStart] || 0) + 1;
      }
    }

    const topIps = Object.entries(byIp)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([ip, count]) => {
        const entry = { ip, count };
        if (ipGeo[ip]) {
          entry.geo = ipGeo[ip];
        }
        if (ipPorts[ip]) {
          entry.ports = Object.entries(ipPorts[ip])
            .map(([port, c]) => ({ port: Number(port), count: c }))
            .sort((a, b) => b.count - a.count);
        }
        if (ipPayloads[ip]) entry.payloads = ipPayloads[ip];
        return entry;
      });

    const topPorts = Object.entries(byPort)
      .sort((a, b) => b[1] - a[1])
      .map(([port, count]) => ({ port: Number(port), count }));

    const countryCounts = Object.values(byCountry)
      .sort((a, b) => b.count - a.count);

    const topCountries = countryCounts.slice(0, 20);

    const hourly = [];
    for (let ms = firstHourStart; ms <= nowHourStart; ms += HOUR_MS) {
      const d = new Date(ms);
      hourly.push({
        bucket: d.toISOString(),
        hour: String(d.getUTCHours()).padStart(2, '0') + ':00',
        count: byHour[ms] || 0,
      });
    }

    const recentPayloads = this.connections
      .filter(c => c.payload)
      .slice(-10)
      .reverse()
      .map(c => ({ ip: c.ip, port: c.port, timestamp: c.timestamp, payload: c.payload, geo: c.geo || null }));

    // SSH-specific aggregations
    const sshConnections = this.connections.filter(c => c.banner || c.clientVersion);
    // Use a null-prototype object so attacker-controlled clientVersion strings
    // like `__proto__` or `constructor` cannot trigger prototype pollution.
    const clientVersions = Object.create(null);
    for (const conn of sshConnections) {
      if (conn.clientVersion) {
        clientVersions[conn.clientVersion] = (clientVersions[conn.clientVersion] || 0) + 1;
      }
    }

    // Count total credential attempts and collect the most recent 20
    // by iterating newest-first, avoiding a large intermediate array.
    let totalCredentialAttempts = 0;
    const maxRecentCreds = 20;
    const recentCredentials = [];
    for (let i = sshConnections.length - 1; i >= 0; i--) {
      const conn = sshConnections[i];
      if (conn.credentials) {
        totalCredentialAttempts += conn.credentials.length;
        if (recentCredentials.length < maxRecentCreds) {
          for (let j = conn.credentials.length - 1; j >= 0 && recentCredentials.length < maxRecentCreds; j--) {
            const cred = conn.credentials[j];
            recentCredentials.push({
              ip: conn.ip,
              timestamp: conn.timestamp,
              username: cred.username,
              password: maskPassword(cred.password),
              passwordHash: cred.passwordHash || null,
              type: 'SSH',
            });
          }
        }
      }
    }

    // Collect HTTP credential attempts (passwordHash is stored but raw password is not)
    const httpCredentialAttempts = [];
    for (let i = this.connections.length - 1; i >= 0 && httpCredentialAttempts.length < 50; i--) {
      const conn = this.connections[i];
      if (inferSource(conn) === 'http' && (conn.username || conn.passwordHash)) {
        httpCredentialAttempts.push({
          ip: conn.ip,
          timestamp: conn.timestamp,
          username: conn.username || null,
          password: maskPassword('********'),
          passwordHash: conn.passwordHash || null,
          type: 'HTTP',
        });
      }
    }

    const uniqueClientVersions = Object.keys(clientVersions).length;

    const topClientVersions = Object.entries(clientVersions)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([version, count]) => ({ version, count }));

    // Combined credential attempts (SSH + HTTP), newest first
    const allCredentialAttempts = [...recentCredentials, ...httpCredentialAttempts]
      .sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)))
      .slice(0, 30);

    return {
      totalConnections: this.connections.length,
      connectionsLast24h: recent.length,
      uniqueIps: Object.keys(byIp).length,
      uniqueCountries: countryCounts.length,
      topIps,
      topPorts,
      countryCounts,
      topCountries,
      hourlyLast24h: hourly,
      recentPayloads,
      vectorBreakdown,
      credentialAttempts: allCredentialAttempts,
      ssh: {
        totalSshConnections: sshConnections.length,
        uniqueClientVersions,
        totalCredentialAttempts,
        topClientVersions,
        recentCredentials,
      },
    };
  }

  async save() {
    if (this.isSaving) return this.savePromise;
    this.isSaving = true;
    this.savePromise = (async () => {
      try {
        const dir = dirname(config.honeypot.dataPath);
        await mkdir(dir, { recursive: true }).catch(() => {});
        await this.rotateIfNeeded();
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

  async rotateIfNeeded() {
    if (!config.honeypot.archiveEnabled) return;
    if (Date.now() - this.lastRotateMs < ROTATE_COOLDOWN_MS) return;

    const dataPath = config.honeypot.dataPath;
    const limitBytes = config.honeypot.maxFileMb * 1024 * 1024;
    let size;
    try {
      const info = await stat(dataPath);
      size = info.size;
    } catch (err) {
      if (err.code === 'ENOENT') return;
      throw err;
    }
    if (size < limitBytes) return;

    // Advance lastRotateMs before attempting archive writes so a failure
    // (permissions, disk full, etc.) is still throttled to ROTATE_COOLDOWN_MS
    // and doesn't trigger a retry on every subsequent save().
    this.lastRotateMs = Date.now();

    const dir = dirname(dataPath);
    const base = basename(dataPath);
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const archivePath = join(dir, `${base}.${timestamp}.gz`);

    // When NDJSON export is enabled, read the file once so both archives
    // derive from identical content. Otherwise stream straight from disk so
    // RSS stays flat even on large files (rotation is triggered by size).
    // Above archiveNdjsonMaxMb the buffer + JSON.parse cost would defeat the
    // whole memory-bounded goal of this feature, so skip NDJSON in that case.
    let fileContent = null;
    const ndjsonLimitBytes = config.honeypot.archiveNdjsonMaxMb * 1024 * 1024;
    const ndjsonOversized = config.honeypot.archiveNdjson && size > ndjsonLimitBytes;
    if (ndjsonOversized) {
      logger.warn('Skipping NDJSON export: source file exceeds archiveNdjsonMaxMb', {
        path: dataPath,
        sizeBytes: size,
        limitBytes: ndjsonLimitBytes,
      });
    }
    if (config.honeypot.archiveNdjson && !ndjsonOversized) {
      try {
        fileContent = await readFile(dataPath);
      } catch (err) {
        logger.error('Honeypot stats rotation failed: could not read source file', {
          path: dataPath,
          error: err.message,
        });
        return;
      }
    }

    try {
      if (fileContent !== null) {
        const gzip = createGzip();
        const done = pipeline(gzip, createWriteStream(archivePath));
        gzip.end(fileContent);
        await done;
      } else {
        await pipeline(
          createReadStream(dataPath),
          createGzip(),
          createWriteStream(archivePath)
        );
      }
      logger.info(`Honeypot stats archived: ${size} bytes to ${archivePath}`);
    } catch (err) {
      logger.error('Honeypot stats rotation failed: snapshot archive write error', {
        path: archivePath,
        error: err.message,
      });
      return;
    }

    if (fileContent !== null) {
      const ndjsonPath = join(dir, `${base}.${timestamp}.ndjson.gz`);
      try {
        await this.writeNdjsonArchive(ndjsonPath, fileContent);
        logger.info(`Honeypot stats NDJSON export: ${ndjsonPath}`);
      } catch (err) {
        logger.error('Failed to write NDJSON archive', {
          path: ndjsonPath,
          error: err.message,
        });
      }
    }

    // Keep in-memory connections intact. The next save() rewrites the file
    // with the bounded current state (maxRecords + retentionDays), which
    // prunes oldest records from disk without wiping runtime stats.
    await this.pruneArchives();
  }

  async writeNdjsonArchive(ndjsonPath, fileContent) {
    // Parse the same buffer used for the .gz snapshot so both archives
    // correspond to identical data, not live in-memory state that may have
    // mutated during the pipeline.
    const parsed = JSON.parse(fileContent.toString('utf8'));
    const connections = Array.isArray(parsed.connections) ? parsed.connections : [];
    const gzip = createGzip();
    const done = pipeline(gzip, createWriteStream(ndjsonPath));
    for (const conn of connections) {
      if (!gzip.write(JSON.stringify(conn) + '\n')) {
        await new Promise(resolve => gzip.once('drain', resolve));
      }
    }
    gzip.end();
    await done;
  }

  async pruneArchives() {
    const dir = dirname(config.honeypot.dataPath);
    const base = basename(config.honeypot.dataPath);
    const prefix = `${base}.`;
    const suffix = '.gz';
    const ndjsonSuffix = '.ndjson';
    try {
      const entries = await readdir(dir);
      // Group by rotation timestamp so the snapshot (`{base}.{ts}.gz`) and
      // its NDJSON export (`{base}.{ts}.ndjson.gz`) are pruned together and
      // count as one archive toward maxArchives.
      const groups = new Map();
      for (const name of entries) {
        if (!name.startsWith(prefix) || !name.endsWith(suffix)) continue;
        const stem = name.slice(prefix.length, -suffix.length);
        const key = stem.endsWith(ndjsonSuffix)
          ? stem.slice(0, -ndjsonSuffix.length)
          : stem;
        const paths = groups.get(key) || [];
        paths.push(join(dir, name));
        groups.set(key, paths);
      }
      if (groups.size <= config.honeypot.maxArchives) return;

      const groupInfo = await Promise.all(
        Array.from(groups.values()).map(async paths => {
          const files = (
            await Promise.all(
              paths.map(async path => {
                try {
                  const info = await stat(path);
                  return { path, mtime: info.mtimeMs };
                } catch {
                  return null;
                }
              })
            )
          ).filter(Boolean);
          if (!files.length) return null;
          return {
            paths: files.map(f => f.path),
            mtime: Math.max(...files.map(f => f.mtime)),
          };
        })
      );
      const sorted = groupInfo
        .filter(Boolean)
        .sort((a, b) => b.mtime - a.mtime);
      const toDelete = sorted.slice(config.honeypot.maxArchives);
      for (const group of toDelete) {
        for (const path of group.paths) {
          await unlink(path).catch(err => {
            logger.warn('Failed to delete old honeypot archive', { path, error: err.message });
          });
        }
      }
    } catch (err) {
      logger.warn('Failed to prune honeypot archives', { error: err.message });
    }
  }

  async stop() {
    if (this.saveTimer) clearInterval(this.saveTimer);
    if (this.savePromise) await this.savePromise;
    if (this.dirty) await this.save();
  }
}

export default new HoneypotStats();
