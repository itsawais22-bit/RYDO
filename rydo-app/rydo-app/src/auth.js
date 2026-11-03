'use strict';
const db = require('./db');
const config = require('./config');
const { hashPassword, verifyPassword, sign, verifyToken, generateOtp, hashOtp } = require('./security');
const { sendSms } = require('./sms');

class HttpError extends Error {
  constructor(status, message, code) { super(message); this.status = status; this.code = code; }
}

const PHONE_RE = /^03\d{9}$/;
const nowIso = () => new Date().toISOString();

/* ---------- validation helpers ---------- */
function reqPhone(v) {
  const phone = String(v || '').trim();
  if (!PHONE_RE.test(phone)) throw new HttpError(400, 'Phone number must be 11 digits starting with 03.');
  return phone;
}
function reqPassword(v) {
  const p = String(v || '');
  if (p.length < 6) throw new HttpError(400, 'Password must be at least 6 characters.');
  if (p.length > 128) throw new HttpError(400, 'Password is too long.');
  return p;
}
function reqName(v) {
  const n = String(v || '').trim().replace(/\s+/g, ' ');
  if (n.length < 2 || n.length > 80) throw new HttpError(400, 'Name must be 2-80 characters.');
  return n;
}

const publicUser = (u) => ({
  id: u.id, name: u.name, phone: u.phone, role: u.role,
  avatar: u.avatar_url || null, rating: u.rating, isVerified: !!u.is_verified,
});

/* ---------- OTP ---------- */
const OTP_COOLDOWN_MS = 30 * 1000;

async function issueOtp(phone, purpose) {
  const last = db.prepare(
    'SELECT created_at FROM otp_codes WHERE phone=? AND purpose=? ORDER BY id DESC LIMIT 1'
  ).get(phone, purpose);
  if (last && Date.now() - Date.parse(last.created_at) < OTP_COOLDOWN_MS) {
    throw new HttpError(429, 'Please wait 30 seconds before requesting another code.');
  }
  const code = generateOtp();
  // invalidate any earlier codes for this phone + purpose
  db.prepare('UPDATE otp_codes SET used=1 WHERE phone=? AND purpose=? AND used=0').run(phone, purpose);
  db.prepare('INSERT INTO otp_codes (phone, purpose, code_hash, expires_at) VALUES (?,?,?,?)')
    .run(phone, purpose, hashOtp(phone, code), new Date(Date.now() + config.otpTtlMs).toISOString());
  await sendSms(phone, `Your RYDO verification code is ${code}. It expires in 5 minutes.`);
  return config.exposeDevOtp ? code : undefined;
}

function consumeOtp(phone, purpose, code) {
  const row = db.prepare(
    'SELECT * FROM otp_codes WHERE phone=? AND purpose=? AND used=0 ORDER BY id DESC LIMIT 1'
  ).get(phone, purpose);
  if (!row || Date.parse(row.expires_at) < Date.now()) {
    throw new HttpError(400, 'Code expired. Please request a new one.', 'OTP_EXPIRED');
  }
  if (row.attempts >= config.otpMaxAttempts) {
    db.prepare('UPDATE otp_codes SET used=1 WHERE id=?').run(row.id);
    throw new HttpError(429, 'Too many wrong attempts. Please request a new code.', 'OTP_LOCKED');
  }
  if (row.code_hash !== hashOtp(phone, String(code || '').trim())) {
    db.prepare('UPDATE otp_codes SET attempts=attempts+1 WHERE id=?').run(row.id);
    throw new HttpError(400, 'Incorrect code.', 'OTP_INVALID');
  }
  db.prepare('UPDATE otp_codes SET used=1 WHERE id=?').run(row.id);
}

const startSession = (user) => ({ token: sign({ sub: user.id, role: user.role }), user: publicUser(user) });

/* ---------- handlers ---------- */
async function signup(body) {
  const name = reqName(body.name);
  const phone = reqPhone(body.phone);
  const password = reqPassword(body.password);
  const role = body.role === 'driver' ? 'driver' : 'rider'; // admins can never self-register

  const existing = db.prepare('SELECT id, is_verified FROM users WHERE phone=?').get(phone);
  if (existing && existing.is_verified) {
    throw new HttpError(409, 'This phone number is already registered. Please log in.', 'PHONE_EXISTS');
  }
  const hash = hashPassword(password);
  if (existing) { // never verified: let them restart signup
    db.prepare("UPDATE users SET name=?, password_hash=?, role=?, updated_at=? WHERE id=?")
      .run(name, hash, role, nowIso(), existing.id);
  } else {
    db.prepare('INSERT INTO users (name, phone, password_hash, role) VALUES (?,?,?,?)')
      .run(name, phone, hash, role);
  }
  const devOtp = await issueOtp(phone, 'signup');
  return { message: 'Verification code sent.', phone, ...(devOtp && { devOtp }) };
}

function verifyOtp(body) {
  const phone = reqPhone(body.phone);
  const user = db.prepare('SELECT * FROM users WHERE phone=?').get(phone);
  if (!user) throw new HttpError(404, 'No signup found for this number.');
  consumeOtp(phone, 'signup', body.code);
  db.prepare('UPDATE users SET is_verified=1, last_login_at=?, updated_at=? WHERE id=?')
    .run(nowIso(), nowIso(), user.id);
  return startSession({ ...user, is_verified: 1 });
}

async function resendOtp(body) {
  const phone = reqPhone(body.phone);
  const user = db.prepare('SELECT is_verified FROM users WHERE phone=?').get(phone);
  if (!user || user.is_verified) throw new HttpError(400, 'Nothing to verify for this number.');
  const devOtp = await issueOtp(phone, 'signup');
  return { message: 'New code sent.', ...(devOtp && { devOtp }) };
}

async function login(body) {
  const phone = reqPhone(body.phone);
  const password = String(body.password || '');
  const role = ['rider', 'driver', 'admin'].includes(body.role) ? body.role : 'rider';
  const BAD = new HttpError(401, 'Incorrect phone number or password.', 'BAD_CREDENTIALS');

  const user = db.prepare('SELECT * FROM users WHERE phone=?').get(phone);
  if (!user) { hashPassword(password); throw BAD; } // burn similar time to avoid user enumeration

  if (user.locked_until && Date.parse(user.locked_until) > Date.now()) {
    const mins = Math.ceil((Date.parse(user.locked_until) - Date.now()) / 60000);
    throw new HttpError(429, `Too many failed attempts. Try again in ${mins} minute(s).`, 'LOCKED');
  }
  if (!verifyPassword(password, user.password_hash)) {
    const fails = user.failed_logins + 1;
    const lock = fails >= config.maxFailedLogins ? new Date(Date.now() + config.lockMs).toISOString() : null;
    db.prepare('UPDATE users SET failed_logins=?, locked_until=? WHERE id=?')
      .run(lock ? 0 : fails, lock, user.id);
    throw BAD;
  }
  if (!user.is_verified) {
    const devOtp = await issueOtp(phone, 'signup').catch(() => undefined);
    throw Object.assign(new HttpError(403, 'Phone not verified yet. We sent you a new code.', 'NOT_VERIFIED'),
      { extra: { phone, ...(devOtp && { devOtp }) } });
  }
  if (user.role !== role) {
    throw new HttpError(403, `This account is registered as "${user.role}". Select the correct role.`, 'ROLE_MISMATCH');
  }
  db.prepare('UPDATE users SET failed_logins=0, locked_until=NULL, last_login_at=? WHERE id=?')
    .run(nowIso(), user.id);
  return startSession(user);
}

async function forgotPassword(body) {
  const phone = reqPhone(body.phone);
  const user = db.prepare('SELECT is_verified FROM users WHERE phone=?').get(phone);
  let devOtp;
  if (user && user.is_verified) devOtp = await issueOtp(phone, 'reset').catch((e) => {
    if (e.status === 429) throw e; // cooldown is fine to reveal
    return undefined;
  });
  // identical response whether or not the account exists
  return { message: 'If this number is registered, a reset code has been sent.', ...(devOtp && { devOtp }) };
}

function resetPassword(body) {
  const phone = reqPhone(body.phone);
  const password = reqPassword(body.newPassword);
  const user = db.prepare('SELECT id FROM users WHERE phone=?').get(phone);
  if (!user) throw new HttpError(400, 'Incorrect code.', 'OTP_INVALID');
  consumeOtp(phone, 'reset', body.code);
  db.prepare('UPDATE users SET password_hash=?, failed_logins=0, locked_until=NULL, updated_at=? WHERE id=?')
    .run(hashPassword(password), nowIso(), user.id);
  return { message: 'Password updated. You can log in now.' };
}

/* ---------- authenticated ---------- */
function authenticate(req) {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
  const payload = m && verifyToken(m[1]);
  if (!payload) throw new HttpError(401, 'Please log in.', 'UNAUTHENTICATED');
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(payload.sub);
  if (!user || !user.is_verified) throw new HttpError(401, 'Please log in.', 'UNAUTHENTICATED');
  return user;
}

const me = (user) => ({ user: publicUser(user) });

function updateProfile(user, body) {
  const name = body.name !== undefined ? reqName(body.name) : user.name;
  let avatar = user.avatar_url;
  if (body.avatar !== undefined) {
    const a = String(body.avatar || '').trim();
    if (a && !/^https?:\/\/[^\s]{1,500}$/i.test(a)) throw new HttpError(400, 'Profile picture must be an http(s) URL.');
    avatar = a || null;
  }
  db.prepare('UPDATE users SET name=?, avatar_url=?, updated_at=? WHERE id=?').run(name, avatar, nowIso(), user.id);
  return { user: publicUser({ ...user, name, avatar_url: avatar }) };
}

module.exports = {
  HttpError, signup, verifyOtp, resendOtp, login, forgotPassword, resetPassword,
  authenticate, me, updateProfile,
};
