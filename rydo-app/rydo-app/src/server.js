'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const config = require('./config');
const auth = require('./auth');

const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.webp': 'image/webp', '.woff2': 'font/woff2',
};

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
};

/* ---------- tiny in-memory rate limiter (per IP) ---------- */
const hits = new Map();
function rateLimited(ip, limit, windowMs) {
  const now = Date.now();
  const rec = hits.get(ip);
  if (!rec || now > rec.reset) { hits.set(ip, { count: 1, reset: now + windowMs }); return false; }
  return ++rec.count > limit;
}
setInterval(() => { const n = Date.now(); for (const [k, v] of hits) if (n > v.reset) hits.delete(k); }, 60000).unref();

/* ---------- helpers ---------- */
function send(res, status, data, headers = {}) {
  const body = JSON.stringify(data);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...SECURITY_HEADERS, ...headers });
  res.end(body);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0, tooBig = false; const chunks = [];
    req.on('data', (c) => {
      if (tooBig) return;
      size += c.length;
      if (size > 10 * 1024) { tooBig = true; chunks.length = 0; reject(new auth.HttpError(413, 'Request too large.')); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (tooBig) return;
      if (!chunks.length) return resolve({});
      try {
        const v = JSON.parse(Buffer.concat(chunks).toString());
        resolve(v && typeof v === 'object' && !Array.isArray(v) ? v : {});
      } catch { reject(new auth.HttpError(400, 'Invalid JSON.')); }
    });
    req.on('error', reject);
  });
}

/* ---------- API routes ---------- */
const routes = {
  'POST /api/auth/signup':          (req, body) => auth.signup(body),
  'POST /api/auth/verify-otp':      (req, body) => auth.verifyOtp(body),
  'POST /api/auth/resend-otp':      (req, body) => auth.resendOtp(body),
  'POST /api/auth/login':           (req, body) => auth.login(body),
  'POST /api/auth/forgot-password': (req, body) => auth.forgotPassword(body),
  'POST /api/auth/reset-password':  (req, body) => auth.resetPassword(body),
  'GET /api/auth/me':               (req) => auth.me(auth.authenticate(req)),
  'PUT /api/auth/profile':          (req, body) => auth.updateProfile(auth.authenticate(req), body),
  'GET /api/health':                () => ({ ok: true }),
};

async function handleApi(req, res, pathname) {
  try {
    const handler = routes[`${req.method} ${pathname}`];
    if (!handler) {
      const known = Object.keys(routes).some((k) => k.endsWith(` ${pathname}`));
      throw new auth.HttpError(known ? 405 : 404, known ? 'Method not allowed.' : 'Not found.');
    }
    const ip = req.socket.remoteAddress || 'unknown';
    if (req.method === 'POST' && rateLimited(ip, 40, 15 * 60 * 1000)) {
      throw new auth.HttpError(429, 'Too many requests. Please try again later.');
    }
    const body = req.method === 'GET' ? {} : await readJson(req);
    send(res, 200, await handler(req, body));
  } catch (err) {
    if (err instanceof auth.HttpError) {
      send(res, err.status, { error: err.message, code: err.code, ...(err.extra || {}) });
    } else {
      console.error('[error]', err);
      send(res, 500, { error: 'Something went wrong. Please try again.' });
    }
  }
}

/* ---------- static front-end ---------- */
function serveStatic(req, res, pathname) {
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
  let rel = decodeURIComponent(pathname);
  if (rel === '/') rel = '/rydo.html';
  const file = path.normalize(path.join(config.publicDir, rel));
  if (!file.startsWith(config.publicDir + path.sep)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream', ...SECURITY_HEADERS });
    res.end(req.method === 'HEAD' ? undefined : data);
  });
}

const server = http.createServer((req, res) => {
  let pathname;
  try { pathname = new URL(req.url, 'http://x').pathname; } catch { res.writeHead(400); return res.end(); }
  if (pathname.startsWith('/api/')) return handleApi(req, res, pathname);
  serveStatic(req, res, pathname);
});

if (require.main === module) {
  server.listen(config.port, () => {
    console.log(`RYDO running at http://localhost:${config.port}`);
    if (config.exposeDevOtp) console.log('Dev mode: OTP codes are printed here and returned by the API.');
  });
}
module.exports = server;
