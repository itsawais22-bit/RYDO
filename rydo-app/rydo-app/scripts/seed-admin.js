'use strict';
// Usage: node scripts/seed-admin.js 03001234567 "StrongPassword" "Admin Name"
// Admins cannot sign up from the website, they are created here.
const db = require('../src/db');
const { hashPassword } = require('../src/security');

const [phone, password, name = 'RYDO Admin'] = process.argv.slice(2);
if (!/^03\d{9}$/.test(phone || '') || !password || password.length < 8) {
  console.error('Usage: node scripts/seed-admin.js <03XXXXXXXXX> <password (8+ chars)> ["Name"]');
  process.exit(1);
}
const hash = hashPassword(password);
const ex = db.prepare('SELECT id FROM users WHERE phone=?').get(phone);
if (ex) db.prepare("UPDATE users SET role='admin', is_verified=1, password_hash=?, name=? WHERE id=?").run(hash, name, ex.id);
else db.prepare("INSERT INTO users (name, phone, password_hash, role, is_verified) VALUES (?,?,?, 'admin', 1)").run(name, phone, hash);
console.log(`Admin ready: ${name} (${phone})`);
