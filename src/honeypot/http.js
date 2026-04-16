import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { URL } from 'node:url';
import config from '../../config.js';
import logger from '../utils/logger.js';
import { sanitizeIp } from '../utils/sanitize.js';
import honeypotStats from './stats.js';

let server = null;

// --- Known scanner tool signatures ---

const SCANNER_SIGNATURES = [
  'sqlmap', 'nikto', 'hydra', 'nmap', 'masscan', 'zgrab', 'gobuster',
  'dirbuster', 'wfuzz', 'ffuf', 'nuclei', 'burp', 'zap', 'arachni',
  'skipfish', 'whatweb', 'wpscan', 'joomscan', 'acunetix', 'nessus',
  'openvas', 'metasploit', 'curl/', 'wget/', 'python-requests', 'go-http-client',
  'java/', 'libwww-perl', 'scrapy', 'httpclient', 'php/',
];

function detectScannerTool(userAgent) {
  if (!userAgent) return null;
  const ua = userAgent.toLowerCase();
  for (const sig of SCANNER_SIGNATURES) {
    if (ua.includes(sig)) return sig;
  }
  return null;
}

// --- Fake login page HTML ---

function wpLoginPage() {
  return `<!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<meta name="viewport" content="width=device-width">
<title>Log In &lsaquo; WordPress &mdash; WordPress</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #f1f1f1; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif; min-height: 100vh; }
  #login { width: 320px; margin: 8% auto; padding: 20px 0; }
  #login h1 { text-align: center; margin-bottom: 24px; }
  #login h1 a { background-image: url('data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 80 80%22%3E%3Cpath fill=%22%233858E9%22 d=%22M40 0C18 0 0 18 0 40s18 40 40 40 40-18 40-40S62 0 40 0zm0 8.5c5 0 9.7 1.2 13.9 3.3L21.5 59.8C13.3 54.2 8.5 45.1 8.5 35c0-17.4 14.1-31.5 31.5-31.5zm0 63c-4.3 0-8.4-.9-12.2-2.5l13-37.7 13.3 36.5c.1.2.2.3.3.5-4.5 2.1-9.4 3.2-14.4 3.2z%22/%3E%3C/svg%3E'); width: 84px; height: 84px; display: block; text-indent: -9999px; background-size: 84px; margin: 0 auto; }
  .login-form { background: #fff; border: 1px solid #c3c4c7; border-radius: 4px; padding: 26px 24px; margin-top: 20px; box-shadow: 0 1px 3px rgba(0,0,0,.04); }
  .login-form label { display: block; margin-bottom: 3px; font-size: 14px; color: #1e1e1e; }
  .login-form input[type="text"], .login-form input[type="password"] { width: 100%; padding: 3px 5px; font-size: 24px; border: 1px solid #8c8f94; border-radius: 4px; margin-bottom: 16px; }
  .login-form .forgetmenot { float: left; margin-bottom: 16px; }
  .login-form input[type="submit"] { float: right; background: #2271b1; border: 1px solid #2271b1; color: #fff; border-radius: 3px; padding: 0 12px; height: 36px; font-size: 13px; cursor: pointer; min-width: 100px; }
  .login-form input[type="submit"]:hover { background: #135e96; }
  .clear { clear: both; }
  #login #nav, #login #backtoblog { padding: 0 24px; margin: 16px 0 0; text-align: center; }
  #login a { color: #2271b1; text-decoration: none; font-size: 13px; }
</style>
</head>
<body>
<div id="login">
  <h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
  <div class="login-form">
    <form name="loginform" id="loginform" action="/wp-login.php" method="post">
      <p>
        <label for="user_login">Username or Email Address</label>
        <input type="text" name="log" id="user_login" value="" size="20" autocapitalize="off" autocomplete="username">
      </p>
      <p>
        <label for="user_pass">Password</label>
        <input type="password" name="pwd" id="user_pass" value="" size="20" autocomplete="current-password">
      </p>
      <p class="forgetmenot"><label><input name="rememberme" type="checkbox" id="rememberme" value="forever"> Remember Me</label></p>
      <p class="submit"><input type="submit" name="wp-submit" id="wp-submit" value="Log In"></p>
      <div class="clear"></div>
    </form>
  </div>
  <p id="nav"><a href="/wp-login.php?action=lostpassword">Lost your password?</a></p>
  <p id="backtoblog"><a href="/">&larr; Go to WordPress</a></p>
</div>
</body>
</html>`;
}

function genericAdminPage(path) {
  const title = path === '/dashboard' ? 'Dashboard' : 'Admin Panel';
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} - Login</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #1a1a2e; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
  .login-container { background: #16213e; border-radius: 8px; padding: 40px; width: 380px; box-shadow: 0 4px 20px rgba(0,0,0,.3); }
  .login-container h2 { color: #e94560; text-align: center; margin-bottom: 30px; font-size: 22px; }
  .form-group { margin-bottom: 20px; }
  .form-group label { display: block; color: #a2a8d3; margin-bottom: 6px; font-size: 14px; }
  .form-group input { width: 100%; padding: 12px 16px; background: #0f3460; border: 1px solid #533483; border-radius: 4px; color: #e94560; font-size: 15px; }
  .form-group input:focus { outline: none; border-color: #e94560; }
  .btn-login { width: 100%; padding: 12px; background: #e94560; color: #fff; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; margin-top: 10px; }
  .btn-login:hover { background: #c73651; }
  .footer-text { text-align: center; margin-top: 20px; color: #533483; font-size: 12px; }
</style>
</head>
<body>
<div class="login-container">
  <h2>${title}</h2>
  <form action="${path}" method="post">
    <div class="form-group">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" placeholder="Enter username" autocomplete="username">
    </div>
    <div class="form-group">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" placeholder="Enter password" autocomplete="current-password">
    </div>
    <button type="submit" class="btn-login">Sign In</button>
  </form>
  <p class="footer-text">&copy; 2024 ${title}. All rights reserved.</p>
</div>
</body>
</html>`;
}

function phpMyAdminPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>phpMyAdmin</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #e7e9ed; font-family: sans-serif; }
  #container { width: 500px; margin: 80px auto; }
  .logo { text-align: center; margin-bottom: 10px; }
  .logo h1 { font-size: 28px; color: #333; font-weight: normal; }
  .logo h1 span { color: #f89d27; }
  #loginform { background: #fff; border: 1px solid #ccc; padding: 20px; border-radius: 4px; }
  .item { margin-bottom: 12px; }
  .item label { display: block; margin-bottom: 4px; color: #333; font-size: 14px; }
  .item input[type="text"], .item input[type="password"] { width: 100%; padding: 6px 8px; border: 1px solid #aaa; border-radius: 3px; font-size: 14px; }
  .item select { padding: 6px 8px; border: 1px solid #aaa; border-radius: 3px; font-size: 14px; }
  .btn { background: #f89d27; color: #fff; border: 1px solid #e08a1e; padding: 6px 20px; border-radius: 3px; font-size: 14px; cursor: pointer; margin-top: 8px; }
  .btn:hover { background: #e08a1e; }
  .server-info { background: #f4f4f4; border: 1px solid #ccc; padding: 8px 12px; margin-bottom: 15px; border-radius: 3px; font-size: 13px; color: #666; }
</style>
</head>
<body>
<div id="container">
  <div class="logo"><h1>php<span>My</span>Admin</h1></div>
  <div id="loginform">
    <div class="server-info">Server: localhost</div>
    <form method="post" action="/phpmyadmin">
      <div class="item">
        <label for="input_username">Username:</label>
        <input type="text" name="pma_username" id="input_username" value="" autocomplete="username">
      </div>
      <div class="item">
        <label for="input_password">Password:</label>
        <input type="password" name="pma_password" id="input_password" value="" autocomplete="current-password">
      </div>
      <div class="item">
        <label for="select_server">Server Choice:</label>
        <select name="server" id="select_server">
          <option value="1">localhost</option>
        </select>
      </div>
      <input class="btn" type="submit" value="Go">
    </form>
  </div>
</div>
</body>
</html>`;
}

function invalidCredentialsPage(path, type) {
  if (type === 'wordpress') {
    return `<!DOCTYPE html>
<html lang="en-US">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width">
<title>Log In &lsaquo; WordPress &mdash; WordPress</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #f1f1f1; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; min-height: 100vh; }
  #login { width: 320px; margin: 8% auto; padding: 20px 0; }
  #login h1 { text-align: center; margin-bottom: 24px; }
  #login h1 a { background: #3858E9; width: 84px; height: 84px; display: block; text-indent: -9999px; border-radius: 50%; margin: 0 auto; }
  .login-error { background: #fff; border-left: 4px solid #d63638; border-radius: 4px; padding: 12px; margin-bottom: 20px; box-shadow: 0 1px 1px rgba(0,0,0,.04); font-size: 13px; color: #1e1e1e; }
  .login-error strong { color: #d63638; }
  .login-form { background: #fff; border: 1px solid #c3c4c7; border-radius: 4px; padding: 26px 24px; box-shadow: 0 1px 3px rgba(0,0,0,.04); }
  .login-form label { display: block; margin-bottom: 3px; font-size: 14px; color: #1e1e1e; }
  .login-form input[type="text"], .login-form input[type="password"] { width: 100%; padding: 3px 5px; font-size: 24px; border: 1px solid #8c8f94; border-radius: 4px; margin-bottom: 16px; }
  .login-form input[type="submit"] { float: right; background: #2271b1; border: 1px solid #2271b1; color: #fff; border-radius: 3px; padding: 0 12px; height: 36px; font-size: 13px; cursor: pointer; }
  .clear { clear: both; }
</style>
</head>
<body>
<div id="login">
  <h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
  <div class="login-error"><strong>Error:</strong> The username or password you entered is incorrect. <a href="/wp-login.php?action=lostpassword">Lost your password?</a></div>
  <div class="login-form">
    <form name="loginform" action="/wp-login.php" method="post">
      <p><label for="user_login">Username or Email Address</label><input type="text" name="log" id="user_login" value="" size="20" autocomplete="username"></p>
      <p><label for="user_pass">Password</label><input type="password" name="pwd" id="user_pass" value="" size="20" autocomplete="current-password"></p>
      <p class="forgetmenot"><label><input name="rememberme" type="checkbox" id="rememberme" value="forever"> Remember Me</label></p>
      <p class="submit"><input type="submit" name="wp-submit" id="wp-submit" value="Log In"></p>
      <div class="clear"></div>
    </form>
  </div>
</div>
</body>
</html>`;
  }

  if (type === 'phpmyadmin') {
    return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>phpMyAdmin</title>
<style>body{background:#e7e9ed;font-family:sans-serif;}#container{width:500px;margin:80px auto;}.err{background:#fce4e4;border:1px solid #cc0000;color:#cc0000;padding:10px 15px;border-radius:4px;margin-bottom:15px;font-size:14px;}</style>
</head>
<body><div id="container">
<h1 style="text-align:center;color:#333;font-weight:normal;">php<span style="color:#f89d27;">My</span>Admin</h1>
<div class="err">Cannot log in to the MySQL server. Access denied for user.</div>
<p style="text-align:center;margin-top:20px;"><a href="/phpmyadmin" style="color:#f89d27;">Retry</a></p>
</div></body></html>`;
  }

  // Generic admin
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Login Failed</title>
<style>
  body{background:#1a1a2e;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;}
  .msg{background:#16213e;border-radius:8px;padding:40px;width:380px;text-align:center;box-shadow:0 4px 20px rgba(0,0,0,.3);}
  .msg h2{color:#e94560;margin-bottom:15px;}
  .msg p{color:#a2a8d3;margin-bottom:20px;font-size:14px;}
  .msg a{color:#e94560;text-decoration:none;font-size:14px;}
</style>
</head>
<body><div class="msg"><h2>Login Failed</h2><p>Invalid username or password. Please try again.</p><a href="${path}">&larr; Back to login</a></div></body></html>`;
}

function notFoundPage() {
  return `<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.24.0 (Ubuntu)</center>
</body>
</html>`;
}

// --- Login path routing ---

const LOGIN_PATHS = {
  '/wp-admin': 'wordpress',
  '/wp-login.php': 'wordpress',
  '/admin': 'generic',
  '/login': 'generic',
  '/dashboard': 'generic',
  '/phpmyadmin': 'phpmyadmin',
};

function getLoginPage(path) {
  const type = LOGIN_PATHS[path];
  if (!type) return null;
  if (type === 'wordpress') return wpLoginPage();
  if (type === 'phpmyadmin') return phpMyAdminPage();
  return genericAdminPage(path);
}

// --- Body parser (URL-encoded, capped) ---

function parseBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    let bytes = 0;
    let resolved = false;
    const maxBytes = config.honeypot.maxPayloadBytes;

    function done(value) {
      if (resolved) return;
      resolved = true;
      clearTimeout(timer);
      resolve(value);
    }

    const timer = setTimeout(() => {
      done(Buffer.concat(chunks).toString('utf8'));
      req.destroy();
    }, 10_000);

    req.on('data', chunk => {
      if (bytes < maxBytes) {
        const remaining = maxBytes - bytes;
        const slice = remaining < chunk.length ? chunk.subarray(0, remaining) : chunk;
        chunks.push(slice);
        bytes += slice.length;
      }

      if (bytes >= maxBytes) {
        done(Buffer.concat(chunks).toString('utf8'));
        req.destroy();
      }
    });

    req.on('end', () => {
      done(Buffer.concat(chunks).toString('utf8'));
    });

    req.on('error', () => done(''));
  });
}

function extractCredentials(body, type) {
  const params = new URLSearchParams(body);
  let username = null;
  let password = null;

  if (type === 'wordpress') {
    username = params.get('log');
    password = params.get('pwd');
  } else if (type === 'phpmyadmin') {
    username = params.get('pma_username');
    password = params.get('pma_password');
  } else {
    username = params.get('username') || params.get('user') || params.get('login');
    password = params.get('password') || params.get('pass') || params.get('passwd');
  }

  return {
    username: username ? String(username).slice(0, 256) : null,
    password: password ? String(password).slice(0, 256) : null,
  };
}

// --- HTTP honeypot server ---

export async function startHttpHoneypot(onThreat) {
  if (!config.honeypot.http.enabled) return null;

  // When TCP honeypot is disabled, HTTP honeypot owns the stats lifecycle
  if (!config.honeypot.enabled) {
    await honeypotStats.load();
    honeypotStats.startAutoSave();
  }

  const port = config.honeypot.http.port;

  return new Promise((resolve, reject) => {
    let bound = false;

    server = createServer(async (req, res) => {
      const remoteIp = sanitizeIp(
        req.socket.remoteAddress?.replace('::ffff:', '')
      );
      const timestamp = new Date().toISOString();
      const userAgent = req.headers['user-agent'] || '';
      const method = req.method;
      const rawUrl = req.url || '/';

      let pathname;
      try {
        pathname = new URL(rawUrl, 'http://localhost').pathname.toLowerCase();
      } catch {
        pathname = '/';
      }

      const scannerTool = detectScannerTool(userAgent);
      const type = LOGIN_PATHS[pathname] || null;

      // Log every request
      logger.info('HTTP honeypot request', {
        ip: remoteIp,
        method,
        path: pathname,
        userAgent: userAgent.slice(0, 200),
        scanner: scannerTool,
      });

      // Record in honeypot stats (skip POST to login paths — recorded below with credential details)
      if (!(method === 'POST' && type)) {
        honeypotStats.record({
          ip: remoteIp,
          port,
          timestamp,
          payload: `${method} ${pathname} UA:${userAgent.slice(0, 100)}`,
        });
      }

      // Handle POST (credential capture)
      if (method === 'POST' && type) {
        const body = await parseBody(req);
        const creds = extractCredentials(body, type);

        const passwordHash = creds.password
          ? createHash('sha256').update(creds.password).digest('hex').slice(0, 16)
          : null;

        logger.warn('HTTP honeypot credential attempt', {
          ip: remoteIp,
          path: pathname,
          type,
          username: creds.username,
          passwordHash,
          userAgent: userAgent.slice(0, 200),
          scanner: scannerTool,
          timestamp,
        });

        // Record credential attempt in honeypot stats
        honeypotStats.record({
          ip: remoteIp,
          port,
          timestamp,
          payload: `POST ${pathname} user:${creds.username || '(empty)'}`,
          username: creds.username || null,
          passwordHash,
        });

        // Emit threat for credential attempts
        if (onThreat) {
          const details = [
            `Credential attempt on ${pathname} (${type})`,
            creds.username ? `user: ${creds.username}` : null,
            passwordHash ? `password captured (sha256: ${passwordHash}…)` : null,
            scannerTool ? `tool: ${scannerTool}` : null,
            `UA: ${userAgent.slice(0, 80)}`,
          ].filter(Boolean).join(' — ');

          onThreat({
            rule: 'honeypot-http',
            severity: 'HIGH',
            ip: remoteIp,
            endpoint: `HTTP:${port}${pathname}`,
            timestamp,
            details,
            suggestedAction: 'block',
            source: 'honeypot-http',
          });
        }

        // Return "invalid credentials" response to keep bots engaged
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(invalidCredentialsPage(pathname, type));
        return;
      }

      // Handle GET login pages
      if (method === 'GET' && type) {
        const page = getLoginPage(pathname);

        // Emit threat for scanner tools probing login pages
        if (onThreat && scannerTool) {
          onThreat({
            rule: 'honeypot-http',
            severity: 'MEDIUM',
            ip: remoteIp,
            endpoint: `HTTP:${port}${pathname}`,
            timestamp,
            details: `Scanner probe on ${pathname} — tool: ${scannerTool} — UA: ${userAgent.slice(0, 80)}`,
            suggestedAction: 'monitor',
            source: 'honeypot-http',
          });
        }

        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(page);
        return;
      }

      // All other paths — 404 that looks like a real nginx server
      res.writeHead(404, {
        'Content-Type': 'text/html',
        'Server': 'nginx/1.24.0 (Ubuntu)',
      });
      res.end(notFoundPage());
    });

    server.on('error', err => {
      if (!bound) {
        if (err.code === 'EADDRINUSE') {
          reject(new Error(`HTTP honeypot: port ${port} already in use`));
        } else if (err.code === 'EACCES') {
          reject(new Error(`HTTP honeypot: no permission to bind port ${port}`));
        } else {
          reject(err);
        }
      } else {
        logger.error('HTTP honeypot runtime error', { error: err.message });
      }
    });

    server.listen(port, '0.0.0.0', () => {
      bound = true;
      logger.info(`HTTP honeypot listening on port ${port}`);
      resolve(port);
    });
  });
}

export async function stopHttpHoneypot() {
  if (!server) return;
  await new Promise(resolve => {
    if (server.listening) {
      server.close(resolve);
    } else {
      resolve();
    }
    server = null;
  });

  // Flush stats if HTTP honeypot owns the lifecycle
  if (!config.honeypot.enabled) {
    await honeypotStats.stop();
  }
}
