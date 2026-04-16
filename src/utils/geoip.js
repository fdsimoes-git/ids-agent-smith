import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import config from '../../config.js';
import logger from './logger.js';

// WARNING: The ip-api.com free tier only supports plain HTTP (no TLS).
// Override with GEOIP_API_URL if you have a paid plan that supports HTTPS.
const GEOIP_API_URL = process.env.GEOIP_API_URL || 'http://ip-api.com';

const cache = new Map();
const inFlight = new Map();
const MAX_CACHE = 1000;

// Token-bucket rate limiter: 45 req/min for ip-api.com free tier
const RATE_LIMIT = 45;
const RATE_WINDOW_MS = 60_000;
let tokens = RATE_LIMIT;
let lastRefill = Date.now();

function refillTokens() {
  const now = Date.now();
  const elapsed = now - lastRefill;
  if (elapsed >= RATE_WINDOW_MS) {
    tokens = RATE_LIMIT;
    lastRefill = now;
  } else {
    const refill = Math.floor((elapsed / RATE_WINDOW_MS) * RATE_LIMIT);
    if (refill > 0) {
      tokens = Math.min(RATE_LIMIT, tokens + refill);
      lastRefill = now;
    }
  }
}

const PRIVATE_RANGES = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^0\./,
  /^169\.254\./,
  /^::1$/,
  /^fc00:/i,
  /^fd/i,
  /^fe80:/i,
];

function isPrivateIp(ip) {
  return PRIVATE_RANGES.some(re => re.test(ip));
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

  // Coalesce concurrent lookups for the same IP into a single outbound request
  if (inFlight.has(ip)) return inFlight.get(ip);

  refillTokens();
  if (tokens <= 0) {
    logger.debug('Geo-IP rate limit reached, skipping lookup', { ip });
    return null;
  }
  tokens--;

  const promise = (async () => {
    try {
      const data = await httpGet(
        `${GEOIP_API_URL}/json/${encodeURIComponent(ip)}?fields=country,countryCode,city,isp,org,as,proxy,hosting`
      );

      if (data.status === 'fail') {
        logger.debug('Geo-IP lookup failed', { ip, message: data.message });
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
  inFlight.clear();
}
