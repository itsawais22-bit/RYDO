# RYDO – Login & Sign-up Backend

Node.js + SQLite backend for the RYDO login / sign-up / OTP / reset-password flow.
**No `npm install` needed** – it uses only Node's built-in modules.

## Run it

Requires **Node.js 22.5 or newer** (`node -v`).

```bash
npm start
```

Open **http://localhost:3000** (open the site through this address, not by double-clicking `rydo.html`).
The database file `db/rydo.db` is created automatically on first start.

## Project layout

```
db/schema.sql        <- the database tables (users, otp_codes)
src/server.js        <- HTTP server, routes, static files, rate limit
src/auth.js          <- signup / OTP / login / reset logic
src/security.js      <- scrypt password hashing, JWT, OTP hashing
src/sms.js           <- put your SMS provider here
src/config.js        <- settings (reads optional .env)
scripts/seed-admin.js
public/rydo.html     <- your site (auth forms now call the API)
public/style.css
```

## Database

**users** – id, name, phone (unique, `03XXXXXXXXX`), password_hash (scrypt), role (`rider`/`driver`/`admin`),
is_verified, avatar_url, rating, failed_logins, locked_until, created_at, updated_at, last_login_at

**otp_codes** – phone, purpose (`signup`/`reset`), code_hash, attempts, used, expires_at, created_at

Passwords and OTP codes are stored hashed, never in plain text.

## API

| Method | Endpoint | Body | Purpose |
|---|---|---|---|
| POST | `/api/auth/signup` | name, phone, password, role (`rider`/`driver`) | Create account, send OTP |
| POST | `/api/auth/verify-otp` | phone, code | Verify phone, returns `token` + `user` |
| POST | `/api/auth/resend-otp` | phone | New signup code (30 s cooldown) |
| POST | `/api/auth/login` | phone, password, role | Returns `token` + `user` |
| POST | `/api/auth/forgot-password` | phone | Send reset code |
| POST | `/api/auth/reset-password` | phone, code, newPassword | Set new password |
| GET | `/api/auth/me` | – (Bearer token) | Current user |
| PUT | `/api/auth/profile` | name, avatar (Bearer token) | Update profile |

Send the token as `Authorization: Bearer <token>` (the site stores it in `localStorage`).

## Create an admin

Admins can't sign up from the website. Create one from the terminal:

```bash
node scripts/seed-admin.js 03001234567 "YourStrongPassword" "Your Name"
```

## Before going live

1. **SMS:** OTP codes are currently printed in the server console and shown in the OTP popup ("dev mode").
   Add your SMS provider's call in `src/sms.js`, then run with `NODE_ENV=production`
   (this automatically stops exposing codes).
2. **Secret:** create a `.env` file (see `.env.example`) with a long random `JWT_SECRET`.
3. **HTTPS:** put the app behind HTTPS (e.g. Nginx / a host that provides TLS).

## Built-in protections

scrypt password hashing · account lock for 15 min after 5 wrong passwords · OTP expires in 5 min and
locks after 5 wrong tries · per-IP rate limit · admin role can't be self-assigned · same response for
unknown/known numbers on password reset · request size limit · path-traversal-safe static server.
