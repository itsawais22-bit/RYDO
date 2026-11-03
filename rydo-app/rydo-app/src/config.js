'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Minimal .env loader (no dotenv dependency)
const envFile = path.join(__dirname, '..', '.env');
if (fs.existsSync(envFile)) {
  for (const line of fs.readFileSync(envFile, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/i);
    if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^['"]|['"]$/g, '');
  }
}

const isProd = process.env.NODE_ENV === 'production';
let secret = process.env.JWT_SECRET;
if (!secret) {
  if (isProd) { console.error('JWT_SECRET must be set in production.'); process.exit(1); }
  secret = crypto.randomBytes(32).toString('hex'); // dev only: sessions reset on restart
  console.warn('[config] JWT_SECRET not set - using a temporary one (logins reset on restart).');
}

module.exports = {
  isProd,
  port: Number(process.env.PORT) || 3000,
  jwtSecret: secret,
  tokenTtlSeconds: Number(process.env.TOKEN_TTL_SECONDS) || 60 * 60 * 24 * 7,
  dbPath: process.env.DB_PATH || path.join(__dirname, '..', 'db', 'rydo.db'),
  publicDir: path.join(__dirname, '..', 'public'),
  otpTtlMs: 5 * 60 * 1000,
  otpMaxAttempts: 5,
  maxFailedLogins: 5,
  lockMs: 15 * 60 * 1000,
  // Until an SMS provider is plugged in (see src/sms.js) the code is returned in the API
  // response and printed to the console. Automatically OFF in production.
  exposeDevOtp: !isProd && process.env.EXPOSE_DEV_OTP !== 'false',
};
