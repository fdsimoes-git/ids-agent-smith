import { checkBruteForce } from './brute-force.js';
import { checkPortScan } from './port-scan.js';
import { checkHttpFlood } from './http-flood.js';
import { checkErrorSpike } from './error-spike.js';
import { checkSsh } from './ssh.js';
import { checkUserAgent } from './user-agent.js';
import { checkGeo } from './geo.js';
import { checkPayload } from './payload.js';
import { checkBannedIp } from './banned-ip.js';
import { identifyOrigin, describeStatus } from '../utils/origin-identifier.js';

const detectors = [
  checkBannedIp,    // must run first to track ban/unban state
  checkBruteForce,
  checkPortScan,
  checkHttpFlood,
  checkErrorSpike,
  checkSsh,
  checkUserAgent,
  checkGeo,
  checkPayload,
];

const MAX_UA_LENGTH = 120;

function buildEnrichment(event) {
  switch (event.source) {
    case 'nginx': {
      const enrichment = { protocol: 'HTTP' };
      if (event.method) enrichment.httpMethod = event.method;
      if (event.status) {
        enrichment.statusCode = event.status;
        const label = describeStatus(event.status);
        if (label) enrichment.statusLabel = label;
      }
      if (event.userAgent) {
        enrichment.userAgent = event.userAgent.length > MAX_UA_LENGTH
          ? event.userAgent.slice(0, MAX_UA_LENGTH) + '…'
          : event.userAgent;
        const origin = identifyOrigin(event.userAgent);
        if (origin) enrichment.origin = origin;
      }
      return enrichment;
    }
    case 'auth': {
      const enrichment = { protocol: 'SSH' };
      if (event.method) enrichment.authMethod = event.method;
      return enrichment;
    }
    case 'ufw': {
      const enrichment = {
        protocol: event.proto ? `Firewall/${event.proto.toUpperCase()}` : 'Firewall',
      };
      if (event.dpt) enrichment.destPort = event.dpt;
      return enrichment;
    }
    case 'fail2ban': {
      const enrichment = { protocol: 'Fail2ban' };
      if (event.jail) enrichment.jail = event.jail;
      return enrichment;
    }
    default:
      return null;
  }
}

export function runDetectors(event, store) {
  const threats = [];
  const enrichment = buildEnrichment(event);
  for (const check of detectors) {
    try {
      const threat = check(event, store);
      if (threat) {
        if (enrichment) Object.assign(threat, enrichment);
        threats.push(threat);
      }
    } catch {
      // Individual detector failure should not break the pipeline
    }
  }
  return threats;
}
