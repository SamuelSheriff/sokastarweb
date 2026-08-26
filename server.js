/**
 * Sokastar — Safaricom Daraja C2B Server
 * ----------------------------------------
 * Receives M-Pesa payments via Safaricom Daraja Standard C2B URL Registration
 * and stores confirmed payments in Supabase so the dashboard shows them in
 * real time.
 *
 * Flow:
 *   1. (One-time) Admin calls POST /api/register-urls to register our
 *      Validation + Confirmation URLs with Safaricom
 *   2. Customer pays manually: M-Pesa → Lipa na M-Pesa → Buy Goods →
 *      enters Till Number + Amount → enters PIN
 *   3. Safaricom POSTs to /webhook/c2b/validate → we accept (ResultCode 0)
 *   4. Safaricom POSTs to /webhook/c2b/confirm → we save to Supabase
 *
 * Required env:
 *   DARAJA_CONSUMER_KEY       from developer.safaricom.co.ke
 *   DARAJA_CONSUMER_SECRET    from developer.safaricom.co.ke
 *   MPESA_SHORTCODE           your Till / Head Office number
 *   DARAJA_ENV                "sandbox" or "production" (default: sandbox)
 *   ADMIN_API_KEY             protects the dashboard + admin endpoints
 *   SUPABASE_URL / SUPABASE_KEY
 *
 * SMS (Africa's Talking) env:
 *   SMS_ENABLED               "true" to enable SMS features (default: false)
 *   AFRICASTALKING_USERNAME   your AT username (use "sandbox" for testing)
 *   AFRICASTALKING_API_KEY    your AT API key
 *   AFRICASTALKING_SENDER_ID  alphanumeric Sender ID e.g. "SOKASTAR" (optional)
 *   SMS_PAYMENT_TEMPLATE      custom payment confirmation message template
 *                             Placeholders: {name} {amount} {package} {mpesa}
 */

require('dotenv').config();

const express    = require('express');
const path       = require('path');
const rateLimit  = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const { looksHashed, decodeHash, primeCache } = require('./msisdn-decoder');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Config ────────────────────────────────────────────────────────────────────
// Secrets are loaded exclusively from environment variables (via .env locally
// or the host platform's config panel in production). No hardcoded defaults.
const ADMIN_API_KEY          = process.env.ADMIN_API_KEY;
const SUPABASE_URL           = process.env.SUPABASE_URL;
const SUPABASE_KEY           = process.env.SUPABASE_KEY;
const ADMIN_EMAIL            = process.env.ADMIN_EMAIL;
let ADMIN_PASSWORD           = process.env.ADMIN_PASSWORD;

// Session key isolation
const SESSION_SECRET         = process.env.SESSION_SECRET || (ADMIN_API_KEY ? ADMIN_API_KEY + '_session_hmac_v1' : 'sokastar_fallback_session_secret');

// ── Password Hashing Helpers (Node.js native scrypt) ─────────────────────────
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(password, salt, 64).toString('hex');
  return `$scrypt$N=16384,r=8,p=1$${salt}$${derivedKey}`;
}

function verifyPassword(password, storedPasswordOrHash) {
  if (!storedPasswordOrHash || !password) return false;
  if (!storedPasswordOrHash.startsWith('$scrypt$')) {
    const bufferA = Buffer.from(String(password));
    const bufferB = Buffer.from(String(storedPasswordOrHash));
    if (bufferA.length !== bufferB.length) return false;
    return crypto.timingSafeEqual(bufferA, bufferB);
  }
  try {
    const parts = storedPasswordOrHash.split('$');
    const salt = parts[3];
    const originalHash = parts[4];
    const keyHex = crypto.scryptSync(password, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(keyHex, 'hex'), Buffer.from(originalHash, 'hex'));
  } catch (e) {
    return false;
  }
}

// Load & migrate persisted custom password if it exists
const fs = require('fs');
const passwordFilePath = path.join(__dirname, 'admin_password.json');
if (fs.existsSync(passwordFilePath)) {
  try {
    const data = JSON.parse(fs.readFileSync(passwordFilePath, 'utf8'));
    if (data && data.password) {
      ADMIN_PASSWORD = data.password;
      // Auto-migrate legacy plaintext passwords to salted scrypt hash
      if (!ADMIN_PASSWORD.startsWith('$scrypt$')) {
        const hashed = hashPassword(ADMIN_PASSWORD);
        ADMIN_PASSWORD = hashed;
        fs.writeFileSync(passwordFilePath, JSON.stringify({ password: hashed }), 'utf8');
        console.log('[SECURITY] Migrated legacy admin_password.json to salted scrypt hash.');
      }
    }
  } catch (e) {
    console.error('Failed to read admin_password.json:', e.message);
  }
}

// Support both DARAJA_ and MPESA_ prefixed env var names
const DARAJA_CONSUMER_KEY    = process.env.DARAJA_CONSUMER_KEY    || process.env.MPESA_CONSUMER_KEY    || '';
const DARAJA_CONSUMER_SECRET = process.env.DARAJA_CONSUMER_SECRET || process.env.MPESA_CONSUMER_SECRET || '';
const MPESA_SHORTCODE        = process.env.MPESA_SHORTCODE        || '4053789';
const MPESA_TILL             = process.env.MPESA_TILL_NUMBER      || '6884892';
const DARAJA_ENV             = process.env.DARAJA_ENV             || process.env.MPESA_ENV || 'sandbox';

// ── Startup Validation ────────────────────────────────────────────────────────
// Fail fast at boot time if any critical secret is missing or left as the
// example placeholder value — prevents silent misconfiguration.
(function validateConfig() {
  const required = {
    ADMIN_API_KEY:  ADMIN_API_KEY,
    SUPABASE_URL:   SUPABASE_URL,
    SUPABASE_KEY:   SUPABASE_KEY,
    ADMIN_EMAIL:    ADMIN_EMAIL,
    ADMIN_PASSWORD: ADMIN_PASSWORD,
  };
  const missing = Object.entries(required).filter(([, v]) => !v).map(([k]) => k);
  if (missing.length > 0) {
    console.error('\n[FATAL] Missing required environment variables:');
    missing.forEach(k => console.error(`  - ${k}`));
    console.error('\nCopy .env.example to .env and fill in your values.\n');
    process.exit(1);
  }
  if (ADMIN_API_KEY === 'change-this-secret-key') {
    console.error('[FATAL] ADMIN_API_KEY is still set to the default example value.');
    console.error('        Generate a random key and set it in your environment.\n');
    process.exit(1);
  }
  if (ADMIN_PASSWORD && ADMIN_PASSWORD.length < 8) {
    console.warn('[WARN]  ADMIN_PASSWORD is very short. Use a strong password.');
  }
  console.log('[OK]    Environment configuration validated.');
})();

// Safaricom Daraja base URLs
const DARAJA_BASE = DARAJA_ENV === 'production'
  ? 'https://api.safaricom.co.ke'
  : 'https://sandbox.safaricom.co.ke';

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// ── Africa's Talking SMS ──────────────────────────────────────────────────────
const SMS_ENABLED          = (process.env.SMS_ENABLED || 'false').toLowerCase() === 'true';
// Set SMS_AUTO_PAYMENT=false to stop auto-SMS on payment while keeping bulk SMS active
const SMS_AUTO_PAYMENT     = (process.env.SMS_AUTO_PAYMENT || 'true').toLowerCase() !== 'false';
const AT_USERNAME          = process.env.AFRICASTALKING_USERNAME  || 'sandbox';
const AT_API_KEY           = process.env.AFRICASTALKING_API_KEY   || '';
const AT_SENDER_ID         = process.env.AFRICASTALKING_SENDER_ID || null;
const SMS_PAYMENT_TEMPLATE = process.env.SMS_PAYMENT_TEMPLATE ||
  'Hi {name}! We have received your KES {amount} payment for the {package} package. Receipt: {mpesa}. Good luck! - Sokastar';

// atSMS is created fresh per-call inside sendSMS() so key rotation takes
// effect without a server restart. Log the current config at startup only.
if (SMS_ENABLED && AT_API_KEY) {
  console.log(`Africa's Talking SMS enabled (username: ${AT_USERNAME}, sender ID: ${AT_SENDER_ID || 'default'}, auto-payment SMS: ${SMS_AUTO_PAYMENT ? 'ON' : 'OFF'})`);
} else {
  console.log('SMS disabled. Set SMS_ENABLED=true and AFRICASTALKING_API_KEY to enable.');
}

/**
 * sendSMS — send a single SMS via Africa's Talking.
 * Gracefully no-ops if SMS is not configured.
 * @param {string} phone  - E.164 or 07xx format
 * @param {string} message
 * @returns {Promise<{status: string, messageId?: string, error?: string}>}
 */
async function sendSMS(phone, message) {
  // Read credentials fresh from env on every call so key rotation works
  // without a server restart.
  const liveApiKey  = process.env.AFRICASTALKING_API_KEY  || '';
  const liveUser    = process.env.AFRICASTALKING_USERNAME || 'sandbox';
  const liveSender  = process.env.AFRICASTALKING_SENDER_ID || null;

  const normalized = normalizePhone(phone);
  if (!SMS_ENABLED || !liveApiKey || !normalized) {
    const reason = !SMS_ENABLED ? 'SMS disabled' : !liveApiKey ? 'SMS not configured' : 'Invalid phone number';
    return { status: 'skipped', error: reason };
  }
  const recipient = normalized.startsWith('+') ? normalized : `+${normalized}`;
  try {
    const AfricasTalking = require('africastalking');
    const at  = AfricasTalking({ username: liveUser, apiKey: liveApiKey });
    const sms = at.SMS;
    const opts = { to: [recipient], message };
    if (liveSender) opts.from = liveSender;
    let result = await sms.send(opts);
    console.log("Africa's Talking API raw result:", JSON.stringify(result));
    if (result && result.SMSMessageData && result.SMSMessageData.Message === 'InvalidSenderId' && liveSender) {
      console.warn(`Sender ID '${liveSender}' is invalid. Retrying SMS to ${recipient} with default Sender ID...`);
      delete opts.from;
      result = await sms.send(opts);
      console.log("Africa's Talking fallback API raw result:", JSON.stringify(result));
    }
    const r = result && result.SMSMessageData && result.SMSMessageData.Recipients && result.SMSMessageData.Recipients[0]
      ? result.SMSMessageData.Recipients[0]
      : {};
    const status   = (r.status || '').toLowerCase() === 'success' ? 'sent' : 'failed';
    const msgId    = r.messageId || null;
    const errMsg   = status === 'failed' ? (r.status || 'AT error') : null;
    // Persist to Supabase sms_logs (best-effort)
    await supabase.from('sms_logs').insert([{
      id: Date.now(),
      phone: recipient,
      message,
      status,
      error: errMsg,
    }]).then(null, () => {});
    console.log(`SMS ${status} → ${recipient} (${msgId || 'no-id'})`);
    return { status, messageId: msgId, error: errMsg, raw: result };
  } catch (e) {
    console.error('sendSMS error:', e.message);
    await supabase.from('sms_logs').insert([{
      id: Date.now(),
      phone: recipient,
      message,
      status: 'failed',
      error: e.message,
    }]).then(null, () => {});
    return { status: 'failed', error: e.message };
  }
}

/**
 * buildPaymentSMS — fills in the SMS_PAYMENT_TEMPLATE placeholders.
 */
function buildPaymentSMS(name, amount, pkg, mpesa) {
  return SMS_PAYMENT_TEMPLATE
    .replace('{name}',    name    || 'Customer')
    .replace('{amount}',  amount  || '')
    .replace('{package}', pkg     || 'package')
    .replace('{mpesa}',   mpesa   || '');
}

// ── Middleware ────────────────────────────────────────────────────────────────
// Read the raw body of every request and parse JSON regardless of content-type,
// so a callback with an unexpected content-type is never silently dropped.
app.use((req, res, next) => {
  let data = '';
  req.on('data', (chunk) => { data += chunk; });
  req.on('end', () => {
    req.rawBody = data;
    if (data) { try { req.body = JSON.parse(data); } catch (_) { req.body = {}; } }
    else { req.body = {}; }
    if (req.method === 'POST') recordHit(req);
    next();
  });
});

// CORS — restrict to explicitly allowed origins only.
// Set ALLOWED_ORIGINS in .env as a comma-separated list, e.g.:
//   ALLOWED_ORIGINS=https://sokastar.co.ke,https://www.sokastar.co.ke
// If not set, falls back to same-origin only (no CORS header emitted).
const _allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin || '';
  if (_allowedOrigins.length > 0 && _allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Api-Key');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ── Debug capture ───────────────────────────────────────────────────────────
// Last 50 POSTs (any path) in memory, readable at GET /api/debug.
const recentHits = [];
function recordHit(req) {
  recentHits.unshift({
    at: new Date().toISOString(),
    method: req.method,
    path: req.path,
    ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || null,
    contentType: req.headers['content-type'] || null,
    rawBody: req.rawBody || '',
  });
  if (recentHits.length > 50) recentHits.length = 50;
}

// ── Persistent Payment Logs ─────────────────────────────────────────────────
// Every webhook hit is saved to Supabase 'payment_logs' table so we never
// lose visibility into what Safaricom sends us.
async function savePaymentLog(entry) {
  try {
    await supabase.from('payment_logs').insert([{
      id: Date.now(),
      timestamp: new Date().toISOString(),
      path: entry.path || '',
      method: entry.method || 'POST',
      ip: entry.ip || '',
      content_type: entry.contentType || '',
      raw_body: entry.rawBody || '',
      parsed: entry.parsed || null,
      status: entry.status || 'received',
      error: entry.error || null,
      result: entry.result || null,
    }]);
  } catch (e) {
    console.error('Failed to save payment log:', e.message);
  }
}

// ── MSISDN decode cache ───────────────────────────────────────────────────────
// Decoded numbers are stored in an optional Supabase 'msisdn_cache' table so a
// repeat customer never has to be brute-forced twice (survives restarts).
// Gracefully no-ops if the table doesn't exist.
async function cacheGetMsisdn(hash) {
  try {
    const { data } = await supabase.from('msisdn_cache').select('msisdn').eq('hash', hash).maybeSingle();
    return data ? data.msisdn : null;
  } catch (_) { return null; }
}
async function cachePutMsisdn(hash, msisdn) {
  try { await supabase.from('msisdn_cache').upsert([{ hash, msisdn }]); } catch (_) {}
}

// ── Package Detection ─────────────────────────────────────────────────────────
const PKG_MAP = [
  { min: 150, max: 300, name: 'Daily' },
  { min: 45,  max: 64,  name: 'Super MultiBet' },
  { min: 30,  max: 44,  name: 'MidWeek Jackpot' },
  { min: 65,  max: 149, name: 'Mega Jackpot' },
  { min: 15,  max: 29,  name: 'Half Time Full Time' },
];

const crypto = require('crypto');

// Cookie helper
function getCookie(req, name) {
  const cookies = req.headers.cookie;
  if (!cookies) return null;
  const pair = cookies.split(';').map(c => c.trim().split('=')).find(p => p[0] === name);
  return pair ? decodeURIComponent(pair[1]) : null;
}

// Token helpers
function generateToken(email) {
  const expiry = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
  const payload = JSON.stringify({ email, expiry });
  const signature = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  return Buffer.from(payload).toString('base64') + '.' + signature;
}

function verifyToken(token) {
  if (!token) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const payload = Buffer.from(parts[0], 'base64').toString();
  const signature = parts[1];
  const expectedSignature = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  if (signature !== expectedSignature) return false;
  try {
    const data = JSON.parse(payload);
    if (data.expiry < Date.now()) return false;
    return data;
  } catch (_) {
    return false;
  }
}

// requireAdmin Auth Middleware
function requireAdmin(req, res, next) {
  const key = req.headers['x-api-key'] || req.query.key;
  if (key === ADMIN_API_KEY) {
    return next();
  }
  const token = getCookie(req, 'session');
  if (token && verifyToken(token)) {
    return next();
  }
  return res.status(401).json({ error: 'Unauthorized' });
}

// IP Whitelist logic
function isSafaricomIp(ip) {
  if (DARAJA_ENV === 'sandbox') return true;
  const cleanIp = ip.replace(/^::ffff:/, '').trim();
  if (cleanIp === '127.0.0.1' || cleanIp === '::1') return true;
  
  if (process.env.MPESA_IP_WHITELIST) {
    const list = process.env.MPESA_IP_WHITELIST.split(',').map(x => x.trim());
    if (list.includes(cleanIp)) return true;
  }
  
  // Whitelist Safaricom subnets: 196.201.212.*, 196.201.213.*, 196.201.214.*
  if (cleanIp.startsWith('196.201.212.') ||
      cleanIp.startsWith('196.201.213.') ||
      cleanIp.startsWith('196.201.214.')) {
    return true;
  }
  return false;
}

function ipWhitelistMiddleware(req, res, next) {
  const clientIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  if (!isSafaricomIp(clientIp)) {
    console.warn(`[IP Blocked] Unauthorized request to ${req.path} from IP ${clientIp}`);
    savePaymentLog({
      path: req.path,
      method: 'POST',
      ip: clientIp,
      contentType: req.headers['content-type'] || '',
      rawBody: req.rawBody || '',
      parsed: req.body,
      status: 'blocked',
      error: `IP ${clientIp} not whitelisted`,
    }).catch(() => {});
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

function inferPackage(amount) {
  return (PKG_MAP.find(p => amount >= p.min && amount <= p.max) || {}).name || 'Unknown';
}

// ── Helpers ─────────────────────────────────────────────────────────────────
function normalizePhone(input) {
  const digits = String(input).replace(/\D/g, '');
  if (digits.startsWith('254')) return digits;
  if (digits.startsWith('0')) return '254' + digits.slice(1);
  if (digits.startsWith('7') || digits.startsWith('1')) return '254' + digits;
  return digits;
}
function toLocalPhone(msisdn) {
  return (msisdn || '').toString().replace(/^\+?254/, '0');
}
// "20260609120000" (EAT) -> ISO. Returns null if unparseable.
function parseMpesaTimestamp(ts) {
  if (ts == null) return null;
  const s = String(ts);
  if (s.length !== 14) return null;
  const iso = `${s.slice(0,4)}-${s.slice(4,6)}-${s.slice(6,8)}T${s.slice(8,10)}:${s.slice(10,12)}:${s.slice(12,14)}+03:00`;
  const d = new Date(iso);
  return isNaN(d.getTime()) ? null : d.toISOString();
}

// ── Daraja OAuth Token ────────────────────────────────────────────────────────
// Tokens expire in ~3600s. We cache and refresh at 3500s.
let cachedToken = null;
let tokenExpiresAt = 0;

async function getDarajaToken() {
  const now = Date.now();
  if (cachedToken && now < tokenExpiresAt) return cachedToken;

  if (!DARAJA_CONSUMER_KEY || !DARAJA_CONSUMER_SECRET) {
    throw new Error('Daraja credentials not configured (DARAJA_CONSUMER_KEY / DARAJA_CONSUMER_SECRET missing)');
  }

  const credentials = Buffer.from(`${DARAJA_CONSUMER_KEY}:${DARAJA_CONSUMER_SECRET}`).toString('base64');
  const url = `${DARAJA_BASE}/oauth/v1/generate?grant_type=client_credentials`;

  const res = await fetch(url, {
    method: 'GET',
    headers: { Authorization: `Basic ${credentials}` },
  });

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Daraja OAuth failed (HTTP ${res.status}): ${body}`);
  }

  const data = await res.json();
  cachedToken = data.access_token;
  // Refresh 100s before actual expiry
  const expiresIn = parseInt(data.expires_in, 10) || 3600;
  tokenExpiresAt = now + (expiresIn - 100) * 1000;

  console.log(`Daraja OAuth token acquired (expires in ${expiresIn}s)`);
  return cachedToken;
}

// ── Routes ────────────────────────────────────────────────────────────────────

// Mount auth middleware for /api routes
app.use('/api', (req, res, next) => {
  if (req.path === '/login' || req.path === '/logout') {
    return next();
  }
  return requireAdmin(req, res, next);
});


// ── Login Rate Limiter ────────────────────────────────────────────────────────
// Caps login attempts to 5 per IP per 15-minute window to prevent brute-force.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please try again in 15 minutes.' },
  handler: (req, res, next, options) => {
    console.warn(`[Rate Limit] Login blocked for IP: ${req.ip}`);
    res.status(429).json(options.message);
  },
});

// Auth Endpoints
app.post('/api/login', loginLimiter, (req, res) => {
  const { email, password } = req.body || {};
  if (email === ADMIN_EMAIL && verifyPassword(password, ADMIN_PASSWORD)) {
    const token = generateToken(email);
    const isProd = process.env.NODE_ENV === 'production';
    let cookieStr = `session=${encodeURIComponent(token)}; Path=/; HttpOnly; Max-Age=86400; SameSite=Lax`;
    if (isProd) cookieStr += '; Secure';
    res.setHeader('Set-Cookie', cookieStr);
    return res.json({ status: 'ok' });
  }
  // Deliberate delay on failure to slow down automated credential stuffing
  setTimeout(() => res.status(401).json({ error: 'Invalid email or password' }), 500);
});

app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'session=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax');
  res.json({ status: 'ok' });
});

// Admin profile details (Protected by requireAdmin)
app.get('/api/admin/profile', (req, res) => {
  res.json({ email: ADMIN_EMAIL });
});

// Admin change password (Protected by requireAdmin)
app.post('/api/admin/change-password', (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current password and new password are required' });
  }
  if (!verifyPassword(currentPassword, ADMIN_PASSWORD)) {
    return res.status(401).json({ error: 'Incorrect current password' });
  }
  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters long' });
  }

  const hashed = hashPassword(newPassword);
  ADMIN_PASSWORD = hashed;
  const passwordFilePath = path.join(__dirname, 'admin_password.json');
  try {
    fs.writeFileSync(passwordFilePath, JSON.stringify({ password: hashed }), 'utf8');
    res.json({ status: 'ok' });
  } catch (e) {
    console.error('Failed to write admin_password.json:', e.message);
    res.status(500).json({ error: 'Failed to save new password on server' });
  }
});

/**
 * POST /api/register-urls
 * Admin-only: Registers Validation + Confirmation URLs with Safaricom.
 * Only needs to be called once (or when your server URL changes).
 * Body (optional): { callbackBase: "https://your-domain.com" }
 */
app.post('/api/register-urls', async (req, res) => {

  // Use the provided callbackBase or try to infer from Host header
  let callbackBase = (req.body && req.body.callbackBase) || '';
  if (!callbackBase) {
    const proto = req.headers['x-forwarded-proto'] || 'https';
    const host  = req.headers['host'];
    if (host) callbackBase = `${proto}://${host}`;
  }
  if (!callbackBase) {
    return res.status(400).json({ error: 'Could not determine server URL. Pass { callbackBase: "https://your-domain.com" } in the body.' });
  }
  callbackBase = callbackBase.replace(/\/+$/, '');

  // Allow overriding the shortcode per-request. For Buy Goods, C2B URLs must be
  // registered against the STORE / Head-Office number (e.g. 8624979), NOT the
  // customer-facing till or the STK shortcode. Falls back to MPESA_SHORTCODE.
  const shortCode = String((req.body && (req.body.shortCode || req.body.storeNumber)) || MPESA_SHORTCODE);

  try {
    const token = await getDarajaToken();
    const registerUrl = `${DARAJA_BASE}/mpesa/c2b/v2/registerurl`;

    const payload = {
      ShortCode: shortCode,
      ResponseType: 'Completed',
      ConfirmationURL: `${callbackBase}/payment/confirmation`,
      ValidationURL:   `${callbackBase}/payment/validation`,
    };

    console.log('Registering C2B URLs with Safaricom:', JSON.stringify(payload));

    const r = await fetch(registerUrl, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      console.error('Daraja Register URL failed:', JSON.stringify(data));
      return res.status(502).json({ error: 'Safaricom rejected URL registration', response: data });
    }

    console.log('C2B URLs registered successfully:', JSON.stringify(data));
    res.json({
      status: 'ok',
      message: 'Validation & Confirmation URLs registered with Safaricom',
      confirmationUrl: payload.ConfirmationURL,
      validationUrl: payload.ValidationURL,
      safaricomResponse: data,
    });
  } catch (err) {
    console.error('Register URL error:', err.message);
    res.status(502).json({ error: err.message });
  }
});

/**
 * Validation handler — Safaricom calls this BEFORE completing a C2B transaction.
 * Return ResultCode 0 to accept, 1 to reject. Always accept for now.
 * Wired to BOTH the legacy /webhook/c2b/validate path and the clean
 * /payment/validation path (see route registration below).
 */
async function handleC2BValidation(req, res) {
  console.log('C2B Validation request:', JSON.stringify(req.body));

  // Log to Supabase
  await savePaymentLog({
    path: '/webhook/c2b/validate',
    method: 'POST',
    ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || '',
    contentType: req.headers['content-type'] || '',
    rawBody: req.rawBody || '',
    parsed: req.body,
    status: 'accepted',
    result: 'Validation accepted (ResultCode 0)',
  });

  // Accept all payments by default.
  // To reject, return { ResultCode: 1, ResultDesc: "Rejected" }
  res.status(200).json({ ResultCode: 0, ResultDesc: 'Accepted' });
}

/**
 * POST /webhook/c2b/confirm  AND  POST /mpesa/callback
 * Safaricom calls this AFTER a successful C2B payment.
 * We listen on BOTH paths because the registered callback URL may vary.
 */
async function handleC2BConfirmation(req, res) {
  const ack = { ResultCode: 0, ResultDesc: 'Success' };
  console.log('C2B Confirmation received:', JSON.stringify(req.body));

  const logBase = {
    path: '/webhook/c2b/confirm',
    method: 'POST',
    ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || '',
    contentType: req.headers['content-type'] || '',
    rawBody: req.rawBody || '',
    parsed: req.body,
  };

  try {
    const payload = req.body || {};

    // Extract standard C2B fields
    const rawTransId  = String(payload.TransID || payload.transId || '').trim();
    const transId     = rawTransId || null;
    const transTime   = String(payload.TransTime || payload.transTime || '').trim() || null;
    const rawAmount   = parseFloat(payload.TransAmount || payload.transAmount || 0);
    const transAmount = Number.isFinite(rawAmount) ? rawAmount : 0;
    const msisdn      = String(payload.MSISDN || payload.msisdn || '').trim() || null;
    const firstName   = String(payload.FirstName || payload.firstName || '').trim();
    const middleName  = String(payload.MiddleName || payload.middleName || '').trim();
    const lastName    = String(payload.LastName || payload.lastName || '').trim();
    const billRef     = String(payload.BillRefNumber || payload.billRefNumber || '').trim();

    // Validate we have minimum required data
    if (!transId || transAmount <= 0) {
      const reason = !transId ? 'Missing TransID' : `Invalid amount: ${transAmount}`;
      console.warn('C2B confirm: ' + reason, payload);
      await savePaymentLog({ ...logBase, status: 'rejected', error: reason });
      return res.status(200).json(ack);
    }

    const mpesaCode = transId.toUpperCase();
    let   phone     = toLocalPhone(msisdn);
    const amount    = Math.round(transAmount);
    const fullName  = [firstName, middleName, lastName].filter(Boolean).join(' ').trim() || 'M-Pesa Customer';

    // Safaricom masks the phone in Buy Goods callbacks (SHA-256 hash). If we've
    // decoded this customer before, use the cached real number right away;
    // otherwise resolve it in the background after we ack (see below).
    let needsDecode = false;
    if (looksHashed(msisdn)) {
      const cached = await cacheGetMsisdn(String(msisdn).toLowerCase());
      if (cached) { phone = toLocalPhone(cached); primeCache(msisdn, cached); }
      else needsDecode = true;
    }

    // Parse transaction timestamp
    const txDate = parseMpesaTimestamp(transTime) ? new Date(parseMpesaTimestamp(transTime)) : new Date();
    const eat = new Date(txDate.getTime() + 3 * 60 * 60 * 1000);
    const date = eat.toISOString().split('T')[0];
    const time = eat.toISOString().slice(11, 16);

    // Deduplicate by M-Pesa receipt code
    const { data: existing } = await supabase.from('transactions').select('mpesa').eq('mpesa', mpesaCode).maybeSingle();
    if (existing) {
      console.log(`Duplicate M-Pesa code ${mpesaCode} — skipped`);
      await savePaymentLog({ ...logBase, status: 'duplicate', result: `Duplicate ${mpesaCode}` });
      return res.status(200).json(ack);
    }

    const newTx = {
      id: Date.now(),
      phone,
      name: fullName,
      mpesa: mpesaCode,
      amount,
      package: inferPackage(amount),
      date,
      time,
      notes: billRef ? `Ref: ${billRef}` : 'Auto — Daraja C2B',
      source: 'daraja',
    };

    const { error } = await supabase.from('transactions').insert([newTx]);
    if (error) {
      console.error('Supabase insert error:', error.message);
      await savePaymentLog({ ...logBase, status: 'db_error', error: error.message });
      return res.status(200).json(ack);
    }

    console.log(`Payment saved: ${mpesaCode} | ${phone} | ${fullName} | KES ${amount}`);
    await savePaymentLog({ ...logBase, status: 'saved', result: `${mpesaCode} | ${phone} | KES ${amount}` });
    res.status(200).json(ack);

    // ── Background tasks after ACK ──────────────────────────────────────────
    // 1. Send auto-SMS confirmation (if SMS is enabled, auto-payment SMS is on, and phone is known)
    if (SMS_ENABLED && SMS_AUTO_PAYMENT && !needsDecode && phone && phone.length >= 9) {
      const smsBody = buildPaymentSMS(fullName.split(' ')[0], amount, newTx.package, mpesaCode);
      sendSMS(phone, smsBody).catch((e) => console.error('Auto-SMS error:', e.message));
    } else if (SMS_ENABLED && !SMS_AUTO_PAYMENT) {
      console.log(`Auto-payment SMS disabled — skipped for ${mpesaCode}`);
    }

    // 2. Reverse the masked MSISDN to the real number, update the row,
    //    then send the delayed auto-SMS with the decoded number.
    if (needsDecode) {
      const hashLower = String(msisdn).toLowerCase();
      const rowId = newTx.id;
      decodeHash(hashLower).then(async (real) => {
        if (!real) { console.log(`MSISDN decode: no match for ${mpesaCode}`); return; }
        const local = toLocalPhone(real);
        await supabase.from('transactions').update({ phone: local }).eq('id', rowId);
        await cachePutMsisdn(hashLower, real);
        console.log(`MSISDN decoded for ${mpesaCode}: ${local}`);
        // Send delayed SMS with the real number now that we have it
        if (SMS_ENABLED && SMS_AUTO_PAYMENT && local) {
          const smsBody = buildPaymentSMS(fullName.split(' ')[0], amount, newTx.package, mpesaCode);
          sendSMS(local, smsBody).catch((e) => console.error('Delayed auto-SMS error:', e.message));
        } else if (SMS_ENABLED && !SMS_AUTO_PAYMENT) {
          console.log(`Auto-payment SMS disabled — skipped delayed SMS for ${mpesaCode}`);
        }
      }).catch((e) => console.error('MSISDN decode error:', e.message));
    }
  } catch (err) {
    console.error('C2B confirm crash:', err);
    await savePaymentLog({ ...logBase, status: 'crash', error: err.message || String(err) });
    res.status(200).json(ack);
  }
}

// ── Webhook route wiring ──────────────────────────────────────────────────────
// Listen on EVERY path Safaricom might be configured to hit, so whichever URL is
// registered in the Daraja portal works without code changes:
//   • /webhook/c2b/*     — the original paths (currently in the Daraja portal)
//   • /payment/*         — the clean paths Tom requested
//   • /mpesa/callback    — the legacy MPESA_CALLBACK_URL path
app.post(['/webhook/c2b/validate', '/payment/validation'], ipWhitelistMiddleware, handleC2BValidation);
app.post(['/webhook/c2b/confirm', '/payment/confirmation', '/mpesa/callback'], ipWhitelistMiddleware, handleC2BConfirmation);

/**
 * GET /api/transactions — dashboard polling & pagination (X-Api-Key protected)
 * Supports query params:
 *   • page   - 1-indexed page number (default: 1)
 *   • limit  - rows per page (default: 50, max: 1000)
 *   • search - optional search query (matches phone, name, mpesa, package, notes)
 *   • all    - "true" to fetch all records (for CSV exports, capped at 10,000)
 */
app.get('/api/transactions', async (req, res) => {
  const isAll = req.query.all === 'true';
  const search = (req.query.search || '').trim();
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = Math.min(1000, Math.max(1, parseInt(req.query.limit, 10) || 50));

  try {
    if (isAll) {
      let query = supabase.from('transactions').select('*', { count: 'exact' }).order('id', { ascending: false });
      if (search) {
        query = query.or(`phone.ilike.%${search}%,name.ilike.%${search}%,mpesa.ilike.%${search}%,package.ilike.%${search}%,notes.ilike.%${search}%`);
      }
      const { data, count, error } = await query.limit(10000);
      if (error) throw error;
      return res.json({
        transactions: data || [],
        count: count || (data || []).length,
        totalCount: count || (data || []).length,
        page: 1,
        limit: data ? data.length : 0,
        totalPages: 1
      });
    }

    const from = (page - 1) * limit;
    const to = from + limit - 1;

    let query = supabase.from('transactions').select('*', { count: 'exact' }).order('id', { ascending: false });

    if (search) {
      query = query.or(`phone.ilike.%${search}%,name.ilike.%${search}%,mpesa.ilike.%${search}%,package.ilike.%${search}%,notes.ilike.%${search}%`);
    }

    const { data, count, error } = await query.range(from, to);

    if (error) throw error;

    const totalCount = count || 0;
    const totalPages = Math.max(1, Math.ceil(totalCount / limit));

    res.json({
      transactions: data || [],
      count: totalCount,
      totalCount,
      page,
      limit,
      totalPages,
    });
  } catch (err) {
    console.error('Supabase read error:', err.message);
    res.status(500).json({ error: 'Database error' });
  }
});


/**
 * DELETE /api/transactions/:id — dashboard delete (X-Api-Key protected)
 */
app.delete('/api/transactions/:id', async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { error } = await supabase.from('transactions').delete().eq('id', id);
  if (error) { console.error('Supabase delete error:', error.message); return res.status(500).json({ error: 'Database error' }); }
  res.json({ status: 'deleted' });
});

/**
 * POST /api/transactions — manual add from the dashboard (X-Api-Key protected)
 */
app.post('/api/transactions', async (req, res) => {
  const tx = { ...req.body, id: Date.now(), source: req.body.source || 'manual' };
  const { error } = await supabase.from('transactions').insert([tx]);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ status: 'ok', transaction: tx });
});

/**
 * GET /api/debug — recent POSTs received (X-Api-Key protected). Verifies callbacks land.
 */
app.get('/api/debug', (req, res) => {
  res.json({ count: recentHits.length, recent: recentHits });
});

/**
 * GET /api/payment-logs — persistent payment logs from Supabase (X-Api-Key protected).
 * Shows every webhook hit with raw payloads, status, and errors.
 */
app.get('/api/payment-logs', async (req, res) => {
  const { data: logs, error } = await supabase
    .from('payment_logs')
    .select('*')
    .order('id', { ascending: false })
    .limit(100);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ logs: logs || [], count: (logs || []).length });
});

/**
 * DELETE /api/payment-logs — clear all payment logs (X-Api-Key protected).
 */
app.delete('/api/payment-logs', async (req, res) => {
  const { error } = await supabase.from('payment_logs').delete().neq('id', 0);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ status: 'cleared' });
});

// ── SMS Endpoints ─────────────────────────────────────────────────────────────

/**
 * GET /api/sms/status — check configuration state (X-Api-Key protected)
 */
app.get('/api/sms/status', (req, res) => {
  const liveKey = process.env.AFRICASTALKING_API_KEY || '';
  res.json({
    enabled: SMS_ENABLED && !!liveKey,
    autoPayment: SMS_AUTO_PAYMENT,
    username: process.env.AFRICASTALKING_USERNAME || 'sandbox',
    senderId: process.env.AFRICASTALKING_SENDER_ID || null
  });
});

app.get('/api/sms/diagnostic', async (req, res) => {

  const rawKey = process.env.AFRICASTALKING_API_KEY || '';
  const strippedKey = rawKey.startsWith('atsk_') ? rawKey.replace('atsk_', '') : rawKey;

  const maskedRaw = rawKey.length > 10 ? `${rawKey.slice(0, 5)}...${rawKey.slice(-5)}` : 'empty';
  const maskedStripped = strippedKey.length > 10 ? `${strippedKey.slice(0, 5)}...${strippedKey.slice(-5)}` : 'empty';

  const sdkResults = {};
  const httpResults = {};
  const combinations = [
    { username: 'NYAD', keyType: 'raw', key: rawKey },
    { username: 'NYAD', keyType: 'stripped', key: strippedKey },
    { username: 'nyad', keyType: 'raw', key: rawKey },
    { username: 'nyad', keyType: 'stripped', key: strippedKey },
    { username: 'sandbox', keyType: 'raw', key: rawKey },
    { username: 'sandbox', keyType: 'stripped', key: strippedKey }
  ];

  for (const combo of combinations) {
    const label = `${combo.username} with ${combo.keyType} key`;
    
    // 1. SDK Test
    try {
      const AfricasTalking = require('africastalking');
      const at = AfricasTalking({ username: combo.username, apiKey: combo.key });
      const data = await at.APPLICATION.fetchApplicationData();
      sdkResults[label] = { success: true, data };
    } catch (e) {
      sdkResults[label] = { success: false, error: e.message };
    }

    // 2. Direct HTTP Test
    try {
      const isSandbox = combo.username === 'sandbox';
      const baseUrl = isSandbox 
        ? 'https://api.sandbox.africastalking.com/version1/user'
        : 'https://api.africastalking.com/version1/user';
      
      const url = `${baseUrl}?username=${combo.username}`;
      const r = await fetch(url, {
        headers: {
          'Accept': 'application/json',
          'apiKey': combo.key
        }
      });
      const text = await r.text();
      httpResults[label] = { 
        status: r.status, 
        statusText: r.statusText,
        body: text.substring(0, 200) 
      };
    } catch (e) {
      httpResults[label] = { error: e.message };
    }
  }

  res.json({
    rawKeyLength: rawKey.length,
    strippedKeyLength: strippedKey.length,
    maskedRaw,
    maskedStripped,
    hasWhitespace: rawKey !== rawKey.trim(),
    sdkResults,
    httpResults
  });
});

/**
 * POST /api/sms/test
 * Admin-only. Sends a single test SMS to a specific phone number.
 * Body: { phone: "+254712345678", message: "Test message" }
 */
app.post('/api/sms/test', async (req, res) => {

  const liveKey = process.env.AFRICASTALKING_API_KEY || '';
  if (!SMS_ENABLED || !liveKey) {
    return res.status(503).json({ error: 'SMS not enabled on this server.' });
  }

  const { phone, message } = req.body || {};
  if (!phone || !message) {
    return res.status(400).json({ error: 'phone and message are required' });
  }

  const result = await sendSMS(phone, message);
  res.json({ status: result.status, messageId: result.messageId, error: result.error || null, raw: result.raw || null });
});

/**
 * POST /api/sms/send-single
 * Admin-only. Sends a single SMS to a specific phone number.
 * Body: { phone: "+254712345678", message: "Hello there" }
 */
app.post('/api/sms/send-single', async (req, res) => {
  const liveKey = process.env.AFRICASTALKING_API_KEY || '';
  if (!SMS_ENABLED || !liveKey) {
    return res.status(503).json({ error: 'SMS not enabled on this server.' });
  }

  const { phone, message } = req.body || {};
  if (!phone || !message) {
    return res.status(400).json({ error: 'phone and message are required' });
  }

  const result = await sendSMS(phone, message);
  res.json({ status: result.status, messageId: result.messageId, error: result.error || null });
});

/**
 * POST /api/sms/send-bulk
 * Admin-only. Sends a bulk SMS campaign to recipients filtered by package and
 * active-since criteria, then logs the campaign to sms_campaigns.
 *
 * Body:
 *   {
 *     message:    string  — the SMS body
 *     package:    string  — "All" | "Daily" | "Mega Jackpot" | ... (optional)
 *     activeDays: number  — only include phones that paid within N days (0=all time)
 *   }
 */
app.post('/api/sms/send-bulk', async (req, res) => {

  const liveKey    = process.env.AFRICASTALKING_API_KEY  || '';
  const liveUser   = process.env.AFRICASTALKING_USERNAME || 'sandbox';
  const liveSender = process.env.AFRICASTALKING_SENDER_ID || null;

  if (!SMS_ENABLED || !liveKey) {
    return res.status(503).json({ error: 'SMS is not enabled on this server. Set SMS_ENABLED=true and AFRICASTALKING_API_KEY.' });
  }

  const { message, package: pkg, activeDays } = req.body || {};
  if (!message || message.trim().length === 0) {
    return res.status(400).json({ error: 'message is required' });
  }

  try {
    // Fetch all transactions from Supabase
    let query = supabase.from('transactions').select('phone, package, date').not('phone', 'is', null);

    // Filter by package
    if (pkg && pkg !== 'All') {
      query = query.eq('package', pkg);
    }

    // Get Kenya local today date (UTC+3)
    const nowKE = new Date(Date.now() + 3 * 60 * 60 * 1000);
    const todayKE = nowKE.toISOString().split('T')[0];

    // Filter by recency
    if (activeDays === 'today') {
      // Exact match for today (Kenya date)
      query = query.eq('date', todayKE);
    } else if (activeDays && parseInt(activeDays, 10) > 0) {
      const since = new Date(Date.now() + 3 * 60 * 60 * 1000);
      since.setDate(since.getDate() - parseInt(activeDays, 10));
      const sinceDate = since.toISOString().split('T')[0];
      query = query.gte('date', sinceDate);
    }

    const { data: txns, error: fetchErr } = await query;
    if (fetchErr) return res.status(500).json({ error: fetchErr.message });

    // Deduplicate phones (keep unique real phone numbers)
    const seen = new Set();
    const phones = [];
    for (const tx of (txns || [])) {
      const raw = (tx.phone || '').trim();
      // Check for hashed MSISDN on the RAW value before stripping non-digits
      if (!raw || looksHashed(raw)) continue;
      const p = raw.replace(/\D/g, '');
      if (p && p.length >= 9 && !seen.has(p)) {
        seen.add(p);
        phones.push(p);
      }
    }

    if (phones.length === 0) {
      return res.json({ status: 'ok', sent: 0, failed: 0, message: 'No eligible recipients found.' });
    }

    // Send in batches of 100 (AT recommendation)
    const BATCH = 100;
    let sent = 0, failed = 0;
    for (let i = 0; i < phones.length; i += BATCH) {
      const batch = phones.slice(i, i + BATCH).map(p => {
        const norm = normalizePhone(p);
        return norm.startsWith('+') ? norm : `+${norm}`;
      });
      try {
        const opts = { to: batch, message: message.trim() };
        if (liveSender) opts.from = liveSender;
        const AfricasTalking = require('africastalking');
        const at = AfricasTalking({ username: liveUser, apiKey: liveKey });
        const sms = at.SMS;
        let result = await sms.send(opts);
        if (result && result.SMSMessageData && result.SMSMessageData.Message === 'InvalidSenderId' && liveSender) {
          console.warn(`Sender ID '${liveSender}' is invalid for bulk. Retrying batch with default Sender ID...`);
          delete opts.from;
          result = await sms.send(opts);
        }
        const recipients = result && result.SMSMessageData && result.SMSMessageData.Recipients
          ? result.SMSMessageData.Recipients
          : [];
        for (const r of recipients) {
          if ((r.status || '').toLowerCase() === 'success') sent++;
          else failed++;
        }
      } catch (batchErr) {
        console.error('Bulk SMS batch error:', batchErr.message);
        failed += batch.length;
      }
    }

    // Log the campaign to Supabase
    await supabase.from('sms_campaigns').insert([{
      id: Date.now(),
      package_name: pkg || 'All',
      message: message.trim(),
      recipients_count: phones.length,
      sent_count: sent,
      failed_count: failed,
    }]).then(null, () => {});

    res.json({ status: 'ok', sent, failed, totalRecipients: phones.length });
  } catch (err) {
    console.error('send-bulk error:', err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/sms/campaigns — past bulk SMS campaigns (X-Api-Key protected).
 */
app.get('/api/sms/campaigns', async (req, res) => {
  const { data, error } = await supabase
    .from('sms_campaigns')
    .select('*')
    .order('id', { ascending: false })
    .limit(100);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ campaigns: data || [] });
});

/**
 * GET /api/sms/logs — individual SMS delivery logs (X-Api-Key protected).
 */
app.get('/api/sms/logs', async (req, res) => {
  const { data, error } = await supabase
    .from('sms_logs')
    .select('*')
    .order('id', { ascending: false })
    .limit(200);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ logs: data || [] });
});

/**
 * GET /api/sms/estimate — estimate recipient count for given filters (no SMS sent).
 */
app.get('/api/sms/estimate', async (req, res) => {

  const { package: pkg, activeDays } = req.query;
  let query = supabase.from('transactions').select('phone, date').not('phone', 'is', null);
  if (pkg && pkg !== 'All') query = query.eq('package', pkg);

  // Get Kenya local today date (UTC+3)
  const nowKE = new Date(Date.now() + 3 * 60 * 60 * 1000);
  const todayKE = nowKE.toISOString().split('T')[0];

  if (activeDays === 'today') {
    query = query.eq('date', todayKE);
  } else if (activeDays && parseInt(activeDays, 10) > 0) {
    const since = new Date(Date.now() + 3 * 60 * 60 * 1000);
    since.setDate(since.getDate() - parseInt(activeDays, 10));
    query = query.gte('date', since.toISOString().split('T')[0]);
  }
  const { data: txns, error } = await query;
  if (error) return res.status(500).json({ error: error.message });

  const seen = new Set();
  for (const tx of (txns || [])) {
    const raw = (tx.phone || '').trim();
    if (!raw || looksHashed(raw)) continue;
    const p = raw.replace(/\D/g, '');
    if (p && p.length >= 9) seen.add(p);
  }
  res.json({ count: seen.size });
});

// ── Predictions API ───────────────────────────────────────────────────────────
// In-memory fallback when Supabase 'predictions' table doesn't exist yet.
let memPredictions = [];

async function dbGetPredictions(filter) {
  try {
    let q = supabase.from('predictions').select('*').order('match_date', { ascending: true }).order('id', { ascending: false });
    if (filter === 'active')   q = q.in('status', ['pending', 'live']);
    if (filter === 'history')  q = q.in('status', ['won', 'lost', 'void']);
    const { data, error } = await q.limit(200);
    if (error) throw error;
    return data || [];
  } catch (_) {
    // Table may not exist — return in-memory store
    if (filter === 'history')  return memPredictions.filter(p => ['won','lost','void'].includes(p.status));
    if (filter === 'active')   return memPredictions.filter(p => ['pending','live'].includes(p.status));
    return memPredictions;
  }
}

/**
 * GET /api/predictions — public endpoint.
 * Returns today's active tips. Premium & VIP picks are masked for public viewers.
 * Pass ?admin=1&key=ADMIN_API_KEY to see unmasked picks (dashboard use).
 */
app.get('/api/predictions', async (req, res) => {
  const isAdmin = req.query.key === ADMIN_API_KEY || (req.headers['x-api-key'] === ADMIN_API_KEY);
  const tips = await dbGetPredictions('active');
  const result = tips.map(t => {
    if (!isAdmin && (t.tier === 'premium' || t.tier === 'vip')) {
      return { ...t, pick: null, odds: t.tier === 'vip' ? null : t.odds, locked: true };
    }
    return { ...t, locked: false };
  });
  res.json({ predictions: result, count: result.length });
});

/**
 * GET /api/predictions/history — public endpoint.
 * Returns completed predictions with win-rate stats.
 */
app.get('/api/predictions/history', async (req, res) => {
  const limit = Math.min(100, parseInt(req.query.limit, 10) || 30);
  const tier  = req.query.tier || '';
  let history = await dbGetPredictions('history');
  if (tier) history = history.filter(p => p.tier === tier);
  history = history.slice(0, limit);

  const settled = history.filter(p => p.status === 'won' || p.status === 'lost');
  const wins = settled.filter(p => p.status === 'won').length;
  const winRate = settled.length > 0 ? Math.round((wins / settled.length) * 100) : 0;

  res.json({
    history,
    stats: {
      total: settled.length,
      wins,
      losses: settled.length - wins,
      voids: history.filter(p => p.status === 'void').length,
      winRate,
    }
  });
});

/**
 * POST /api/predictions — admin: post a new tip.
 * Body: { homeTeam, awayTeam, league, matchDate, matchTime, pick, odds, tier, notes }
 * tier: "free" | "premium" | "vip"
 */
app.post('/api/predictions', async (req, res) => {
  const { homeTeam, awayTeam, league, matchDate, matchTime, pick, odds, tier, notes } = req.body || {};
  if (!homeTeam || !awayTeam || !pick || !tier) {
    return res.status(400).json({ error: 'homeTeam, awayTeam, pick, and tier are required' });
  }
  const prediction = {
    id: Date.now(),
    home_team:   String(homeTeam).trim(),
    away_team:   String(awayTeam).trim(),
    league:      String(league || '').trim(),
    match_date:  matchDate || new Date().toISOString().split('T')[0],
    match_time:  matchTime || '—',
    pick:        String(pick).trim(),
    odds:        odds ? parseFloat(odds) : null,
    tier:        ['free','premium','vip'].includes(tier) ? tier : 'free',
    status:      'pending',
    notes:       String(notes || '').trim(),
    created_at:  new Date().toISOString(),
  };
  try {
    const { error } = await supabase.from('predictions').insert([prediction]);
    if (error) throw error;
  } catch (_) {
    memPredictions.unshift(prediction);
  }
  res.json({ status: 'ok', prediction });
});

/**
 * PUT /api/predictions/:id — admin: update tip status or score.
 * Body: { status, score, pick, odds }
 * status: "pending" | "live" | "won" | "lost" | "void"
 */
app.put('/api/predictions/:id', async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const updates = {};
  if (req.body.status !== undefined) updates.status = req.body.status;
  if (req.body.score  !== undefined) updates.score  = String(req.body.score).trim();
  if (req.body.pick   !== undefined) updates.pick   = String(req.body.pick).trim();
  if (req.body.odds   !== undefined) updates.odds   = parseFloat(req.body.odds);
  updates.updated_at = new Date().toISOString();

  try {
    const { error } = await supabase.from('predictions').update(updates).eq('id', id);
    if (error) throw error;
  } catch (_) {
    const idx = memPredictions.findIndex(p => p.id === id);
    if (idx !== -1) Object.assign(memPredictions[idx], updates);
  }
  res.json({ status: 'ok' });
});

/**
 * DELETE /api/predictions/:id — admin: remove a tip.
 */
app.delete('/api/predictions/:id', async (req, res) => {
  const id = parseInt(req.params.id, 10);
  try {
    const { error } = await supabase.from('predictions').delete().eq('id', id);
    if (error) throw error;
  } catch (_) {
    memPredictions = memPredictions.filter(p => p.id !== id);
  }
  res.json({ status: 'deleted' });
});

/**
 * Catch-all: log any POST to /webhook/* or /payment/* paths we don't recognize.
 * This catches if Safaricom is hitting a different path than expected.
 */
app.post(['/webhook/*', '/payment/*', '/mpesa/*'], async (req, res) => {
  console.warn('UNKNOWN webhook path hit:', req.path, req.rawBody);
  await savePaymentLog({
    path: req.path,
    method: 'POST',
    ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || '',
    contentType: req.headers['content-type'] || '',
    rawBody: req.rawBody || '',
    parsed: req.body,
    status: 'unknown_path',
    error: `Unrecognized webhook path: ${req.path}`,
  });
  res.status(200).json({ ResultCode: 0, ResultDesc: 'Accepted' });
});

/**
 * GET /health — uptime ping.
 */
app.get('/health', (_, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

app.get('/',      (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/admin', (req, res) => {
  const token = getCookie(req, 'session');
  if (token && verifyToken(token)) {
    return res.sendFile(path.join(__dirname, 'dashboard.html'));
  }
  res.redirect('/login');
});

app.listen(PORT, () => {
  console.log(`\nSokastar Daraja C2B server running on port ${PORT}`);
  console.log(`   POST /webhook/c2b/validate  - Safaricom validation callback`);
  console.log(`   POST /webhook/c2b/confirm   - Safaricom confirmation callback`);
  console.log(`   POST /api/register-urls     - Register URLs with Safaricom (admin)`);
  console.log(`   GET  /api/transactions      - Dashboard polling endpoint`);
  console.log(`   GET  /health                - Uptime monitor ping`);
  console.log(`   Supabase:   ${SUPABASE_URL}`);
  console.log(`   Daraja env: ${DARAJA_ENV} (${DARAJA_BASE})`);
  console.log(`   Shortcode:  ${MPESA_SHORTCODE} (Till: ${MPESA_TILL})`);
  console.log(`   Daraja key: ${DARAJA_CONSUMER_KEY ? 'configured (' + DARAJA_CONSUMER_KEY.slice(0,8) + '...)' : 'MISSING - set DARAJA_CONSUMER_KEY or MPESA_CONSUMER_KEY'}`);
  console.log(`   ADMIN key:  ${ADMIN_API_KEY === 'change-this-secret-key' ? 'USING DEFAULT - SET ENV VAR!' : 'configured'}\n`);
});
