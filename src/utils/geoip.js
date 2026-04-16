import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import config from '../../config.js';
import logger from './logger.js';

// WARNING: The ip-api.com free tier only supports plain HTTP (no TLS).
// Override with GEOIP_API_URL if you have a paid plan that supports HTTPS.
const GEOIP_API_URL = process.env.GEOIP_API_URL || 'http://ip-api.com';

const cache = new Map();
const negCache = new Map();       // failed-lookup negative cache (ip → expiry timestamp)
const NEG_CACHE_TTL = 3_600_000;  // 1 hour
const inFlight = new Map();
const MAX_CACHE = 1000;

// Fixed-window rate limiter: allows up to 45 requests per 60-second window
// for the ip-api.com free tier. The counter resets when the window elapses —
// this is *not* a sliding/rolling window, so up to 90 requests can occur in
// a 60-second span that straddles two windows.
const RATE_LIMIT = 45;
const RATE_WINDOW_MS = 60_000;
let windowRequestCount = 0;
let windowStart = Date.now();

function canConsume() {
  const now = Date.now();
  if (now - windowStart >= RATE_WINDOW_MS) {
    windowRequestCount = 0;
    windowStart = now;
  }
  return windowRequestCount < RATE_LIMIT;
}

const PRIVATE_RANGES = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^0\./,
  /^169\.254\./,
  /^::1$/,
  /^f[cd]/i,   // fc00::/7 — covers both fc… and fd… ULA prefixes
  /^fe80:/i,
];

function stripMappedPrefix(ip) {
  return ip.startsWith('::ffff:') ? ip.slice(7) : ip;
}

function isPrivateIp(ip) {
  return PRIVATE_RANGES.some(re => re.test(stripMappedPrefix(ip)));
}

function httpGet(url) {
  return new Promise((resolve, reject) => {
    const doRequest = url.startsWith('https') ? httpsRequest : httpRequest;
    const req = doRequest(url, { timeout: 5000 }, res => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode}`));
          return;
        }
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error('Invalid JSON response'));
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    req.end();
  });
}

/**
 * Look up geo-IP data for a given IP address.
 * Returns { country, countryCode, city, isp, org, as, proxy, hosting } or null.
 */
export async function lookupIp(ip) {
  if (!config.geoip?.enabled) return null;
  if (!ip || isPrivateIp(ip)) return null;

  if (cache.has(ip)) return cache.get(ip);

  // Short-lived negative cache — avoid re-querying IPs that recently failed
  if (negCache.has(ip)) {
    if (Date.now() < negCache.get(ip)) return null;
    negCache.delete(ip);
  }

  // Coalesce concurrent lookups for the same IP into a single outbound request
  if (inFlight.has(ip)) return inFlight.get(ip);

  if (!canConsume()) {
    logger.debug('Geo-IP rate limit reached, skipping lookup', { ip });
    return null;
  }
  windowRequestCount++;

  const promise = (async () => {
    try {
      const data = await httpGet(
        `${GEOIP_API_URL}/json/${encodeURIComponent(ip)}?fields=country,countryCode,city,isp,org,as,proxy,hosting`
      );

      if (data.status === 'fail') {
        logger.debug('Geo-IP lookup failed', { ip, message: data.message });
        negCache.set(ip, Date.now() + NEG_CACHE_TTL);
        return null;
      }

      const geo = {
        country: data.country || '',
        countryCode: data.countryCode || '',
        city: data.city || '',
        isp: data.isp || '',
        org: data.org || '',
        as: data.as || '',
        proxy: !!data.proxy,
        hosting: !!data.hosting,
      };

      // Evict oldest entry if cache is full
      if (cache.size >= MAX_CACHE) {
        const oldest = cache.keys().next().value;
        cache.delete(oldest);
      }
      cache.set(ip, geo);

      return geo;
    } catch (err) {
      logger.debug('Geo-IP lookup error', { ip, error: err.message });
      negCache.set(ip, Date.now() + NEG_CACHE_TTL);
      return null;
    } finally {
      inFlight.delete(ip);
    }
  })();

  inFlight.set(ip, promise);
  return promise;
}

export function clearCache() {
  cache.clear();
  negCache.clear();
  inFlight.clear();
}
