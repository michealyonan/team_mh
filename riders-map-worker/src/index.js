import { DurableObject } from 'cloudflare:workers';

const MAX_BODY_BYTES = 2_000_000;
const SNAPSHOT_TTL_MS = 15 * 60 * 1000;

/* ---------------- auth / users API (phase 2) ---------------- */

const te = new TextEncoder();
async function sha256hex(s) {
  const b = await crypto.subtle.digest('SHA-256', te.encode(s));
  return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
}
// legacy password hash scheme (kept so existing passwords keep working)
const hp = (u, p) => sha256hex(String(u).toLowerCase() + ':' + p + ':pd1');
// 25 Nov security pass: PBKDF2 password hashing. New/reset passwords get pb2$ format;
// legacy pd1 hashes still verify and upgrade to pb2 on successful login (no lockouts).
const PB_ITER = 100000;
const bytesToHex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
const hexToBytes = (h) => new Uint8Array((String(h).match(/../g) || []).map((x) => parseInt(x, 16)));
async function pbkdf(u, p, salt, iter) {
  const key = await crypto.subtle.importKey('raw', te.encode(String(u).toLowerCase() + ':' + p), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, key, 256);
  return bytesToHex(bits);
}
const hp2new = async (u, p) => {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return 'pb2$' + PB_ITER + '$' + bytesToHex(salt) + '$' + (await pbkdf(u, p, salt, PB_ITER));
};
async function verifyUserPassword(env, u, stored, p) {
  const s = String(stored || '');
  if (s.startsWith('pb2$')) {
    const parts = s.split('$');
    return safeEqual(parts[3] || '', await pbkdf(u, p, hexToBytes(parts[2] || ''), Number(parts[1]) || PB_ITER));
  }
  if (!safeEqual(s, await hp(u, p))) return false;
  try { await env.DB.prepare('UPDATE users SET h=? WHERE u=?').bind(await hp2new(u, p), u).run(); } catch (e) {}
  return true;
}
const randHex = (n) => [...crypto.getRandomValues(new Uint8Array(n))].map((x) => x.toString(16).padStart(2, '0')).join('');
const randCode = (digits) => {
  let s = '';
  const b = crypto.getRandomValues(new Uint8Array(digits));
  for (let i = 0; i < digits; i++) s += String(b[i] % 10);
  return s;
};
const randPassword = () => {
  const abc = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const b = crypto.getRandomValues(new Uint8Array(8));
  let s = '';
  for (let i = 0; i < 8; i++) s += abc[b[i] % abc.length];
  return s;
};

const _aiUse = new Map();
let schemaReady = false;
async function ensureSchema(env) {
  if (schemaReady) return;
  await env.DB.batch([
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS users(
      u TEXT PRIMARY KEY, n TEXT NOT NULL DEFAULT '', r TEXT NOT NULL DEFAULT 'sup',
      s TEXT NOT NULL DEFAULT '', h TEXT NOT NULL DEFAULT '',
      email TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT '', channel TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'active', created_at INTEGER, updated_at INTEGER)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS sessions(
      token TEXT PRIMARY KEY, u TEXT NOT NULL, expires INTEGER NOT NULL, created INTEGER NOT NULL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS codes(
      id INTEGER PRIMARY KEY AUTOINCREMENT, u TEXT NOT NULL, purpose TEXT NOT NULL,
      code_hash TEXT NOT NULL, expires INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
      used INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS recoveries(
      id INTEGER PRIMARY KEY AUTOINCREMENT, u TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
      created INTEGER NOT NULL, resolved INTEGER)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS rl(k TEXT PRIMARY KEY, n INTEGER NOT NULL DEFAULT 0, until INTEGER)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS audit(
      id INTEGER PRIMARY KEY AUTOINCREMENT, u TEXT, n TEXT, r TEXT, ip TEXT, ts INTEGER)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS notifications(
      id INTEGER PRIMARY KEY AUTOINCREMENT, u TEXT NOT NULL, day TEXT NOT NULL,
      title TEXT NOT NULL DEFAULT '', body TEXT NOT NULL DEFAULT '', rider_id TEXT NOT NULL DEFAULT '',
      ts INTEGER NOT NULL)`),
    env.DB.prepare(`CREATE INDEX IF NOT EXISTS notif_ud ON notifications(u, day, id)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS notifications_read(u TEXT PRIMARY KEY, ts INTEGER NOT NULL DEFAULT 0)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT NOT NULL DEFAULT '')`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS push_tokens(u TEXT NOT NULL, token TEXT NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY(u, token))`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS viewer_access(
      viewer_u TEXT NOT NULL, sup_name TEXT NOT NULL, PRIMARY KEY(viewer_u, sup_name))`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS login_fails(
      u TEXT PRIMARY KEY, n INTEGER NOT NULL DEFAULT 0)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS geo(
      u TEXT PRIMARY KEY, lat REAL, lon REAL, acc REAL, ts INTEGER NOT NULL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS rider_states(
      rider_id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', state TEXT NOT NULL DEFAULT '',
      sup TEXT NOT NULL DEFAULT '', updated INTEGER NOT NULL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS form_submissions(id INTEGER PRIMARY KEY AUTOINCREMENT,u TEXT NOT NULL,action TEXT NOT NULL,rider_id TEXT NOT NULL,city TEXT NOT NULL,payload TEXT NOT NULL,result TEXT NOT NULL,ts INTEGER NOT NULL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS chat_messages(
      id INTEGER PRIMARY KEY AUTOINCREMENT, from_u TEXT NOT NULL, to_u TEXT NOT NULL,
      body TEXT NOT NULL, ts INTEGER NOT NULL, read_at INTEGER)`),
    env.DB.prepare(`CREATE INDEX IF NOT EXISTS chat_from ON chat_messages(from_u, to_u, id)`),
    env.DB.prepare(`CREATE INDEX IF NOT EXISTS chat_to ON chat_messages(to_u, from_u, id)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS chat_presence(u TEXT PRIMARY KEY, ts INTEGER NOT NULL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS usage_daily(day TEXT PRIMARY KEY, n INTEGER NOT NULL DEFAULT 0)`),
    env.DB.prepare(`CREATE INDEX IF NOT EXISTS form_submissions_user_ts ON form_submissions(u,ts)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS form_phone_jobs(id INTEGER PRIMARY KEY AUTOINCREMENT,u TEXT NOT NULL,job TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',result TEXT NOT NULL DEFAULT '',ts INTEGER NOT NULL,updated INTEGER NOT NULL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS hiring_requests(id INTEGER PRIMARY KEY AUTOINCREMENT,u TEXT NOT NULL,payload TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',result TEXT NOT NULL DEFAULT '',ts INTEGER NOT NULL,updated INTEGER NOT NULL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS hiring_images(request_id INTEGER NOT NULL,k TEXT NOT NULL,data TEXT NOT NULL,PRIMARY KEY(request_id,k))`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS shift_commands(id INTEGER PRIMARY KEY AUTOINCREMENT,u TEXT NOT NULL,payload TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',result TEXT NOT NULL DEFAULT '',ts INTEGER NOT NULL,updated INTEGER NOT NULL)`),
  ]);
  try { await env.DB.prepare("ALTER TABLE users ADD COLUMN photo TEXT NOT NULL DEFAULT ''").run(); } catch {}
  schemaReady = true;
  // kind column for image messages (added 24 Nov) - CREATE TABLE IF NOT EXISTS
  // won't alter an existing table, so try the ALTER and ignore duplicate-column.
  try { await env.DB.prepare("ALTER TABLE chat_messages ADD COLUMN kind TEXT NOT NULL DEFAULT 'text'").run(); } catch (e) {}
}

/* ---------------- Cloudflare free-quota usage meter (estimate) ----------------
   Counts every request that reaches this worker, batched into one D1 write
   per isolate per minute so the free D1 write quota is never at risk.
   The number is an estimate for THIS worker only; when CF_API_TOKEN and
   CF_ACCOUNT_ID secrets exist, /api/admin/usage answers with the real
   account-wide figure from the Cloudflare GraphQL analytics API instead. */
const QUOTA_DAILY_LIMIT = 100000; // Cloudflare Workers free plan: 100,000 requests/day
const usageMem = { day: null, n: 0, lastFlush: 0 };
const utcDay = (ts) => new Date(ts || Date.now()).toISOString().slice(0, 10);
const nextUtcMidnight = (ts) => { const d = new Date(ts || Date.now()); return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()) + 86400000); };

function bumpUsage(env, ctx) {
  const day = utcDay();
  if (usageMem.day !== day) { usageMem.day = day; usageMem.n = 0; usageMem.lastFlush = 0; }
  usageMem.n++;
  const now = Date.now();
  if (now - usageMem.lastFlush >= 60000) {
    usageMem.lastFlush = now;
    const add = usageMem.n;
    usageMem.n = 0;
    const run = () => env.DB.prepare('INSERT INTO usage_daily(day,n) VALUES(?,?) ON CONFLICT(day) DO UPDATE SET n=n+excluded.n').bind(day, add).run().catch(() => {});
    if (ctx && ctx.waitUntil) ctx.waitUntil(run()); else run();
  }
}

async function usageEstimate(env) {
  const day = utcDay();
  let used = 0;
  try {
    const row = await env.DB.prepare('SELECT n FROM usage_daily WHERE day=?').bind(day).first();
    used = (row && row.n) || 0;
  } catch {}
  if (usageMem.day === day) used += usageMem.n;
  return used;
}

let gqlUsageCache = { day: null, ts: 0, used: null };
async function usageFromCloudflare(env) {
  const day = utcDay();
  if (gqlUsageCache.day === day && gqlUsageCache.used !== null && Date.now() - gqlUsageCache.ts < 120000) return gqlUsageCache.used;
  const start = new Date(nextUtcMidnight().getTime() - 86400000).toISOString();
  const end = new Date().toISOString();
  const query = 'query($acc:String!,$s:DateTime!,$e:DateTime!){viewer{accounts(filter:{accountTag:$acc}){invocationsSeriesAdaptiveGroups(limit:10000,filter:{datetime_geq:$s,datetime_leq:$e}){sum{requests}}}}}';
  const resp = await fetch('https://api.cloudflare.com/client/v4/graphql', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + env.CF_API_TOKEN },
    body: JSON.stringify({ query, variables: { acc: env.CF_ACCOUNT_ID, s: start, e: end } }),
  });
  const data = await resp.json().catch(() => null);
  if (!resp.ok || !data || !data.data || !data.data.viewer) {
    const msg = data && data.errors && data.errors[0] && data.errors[0].message ? data.errors[0].message : ('HTTP ' + resp.status);
    throw new Error(msg);
  }
  const accounts = data.data.viewer.accounts || [];
  let used = 0;
  for (const acc of accounts) for (const g of (acc.invocationsSeriesAdaptiveGroups || [])) used += (g.sum && g.sum.requests) || 0;
  gqlUsageCache = { day, ts: Date.now(), used };
  return used;
}

async function rateLimit(env, key, max, windowMs, lockMs) {
  const now = Date.now();
  const row = await env.DB.prepare('SELECT n, until FROM rl WHERE k=?').bind(key).first();
  if (row) {
    if (row.n >= max && row.until > now) return Math.ceil((row.until - now) / 1000);
    if (row.until <= now) {
      await env.DB.prepare('UPDATE rl SET n=1, until=? WHERE k=?').bind(now + windowMs, key).run();
      return 0;
    }
    const n = row.n + 1;
    const until = n >= max ? now + lockMs : row.until;
    await env.DB.prepare('UPDATE rl SET n=?, until=? WHERE k=?').bind(n, until, key).run();
    return n >= max ? Math.ceil(lockMs / 1000) : 0;
  }
  await env.DB.prepare('INSERT INTO rl(k,n,until) VALUES(?,1,?)').bind(key, now + windowMs).run();
  return 0;
}

// Admin-controlled per-tab visibility (Micheal 25 Nov): settings.hidden_tabs is
// a JSON array of tab ids hidden from every non-admin role. The UI hides the
// tab; this blocks the tab's own API namespaces too (chat, hiring). Tabs whose
// data rides on the shared dashboard endpoints can't be blocked per-tab without
// breaking the dashboard itself, so their enforcement is the UI gate.
async function getHiddenTabs(env) {
  try {
    const row = await env.DB.prepare("SELECT v FROM settings WHERE k='hidden_tabs'").first();
    const a = JSON.parse((row && row.v) || '[]');
    return Array.isArray(a) ? a.map(String) : [];
  } catch (e) { return []; }
}
async function getTabOrder(env) {
  try {
    const row = await env.DB.prepare("SELECT v FROM settings WHERE k='tab_order'").first();
    const a = JSON.parse((row && row.v) || '[]');
    return Array.isArray(a) ? a.map(String) : [];
  } catch (e) { return []; }
}
function tabBlockedFor(hidden, tab, user) { return user && user.r !== 'admin' && hidden.indexOf(tab) >= 0; }

async function getSessionUser(env, request) {
  const h = request.headers.get('Authorization') || '';
  const m = h.match(/^Bearer\s+([0-9a-f]{64})$/i);
  if (!m) return null;
  const row = await env.DB.prepare('SELECT s.token, s.expires, u.u, u.n, u.r, u.s, u.status, u.email, u.phone, u.channel FROM sessions s JOIN users u ON u.u=s.u WHERE s.token=?').bind(m[1].toLowerCase()).first();
  if (!row || row.expires < Date.now() || row.status === 'disabled') return null;
  return { u: row.u, n: row.n, r: row.r, s: row.s, token: row.token, email: row.email, phone: row.phone, channel: row.channel };
}

function cairoDay(ts) {
  return new Intl.DateTimeFormat('en-CA', { timeZone: 'Africa/Cairo', year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date(ts || Date.now()));
}

async function insertNotification(env, u, title, body, riderId) {
  await env.DB.prepare('INSERT INTO notifications(u,day,title,body,rider_id,ts) VALUES(?,?,?,?,?,?)')
    .bind(u, cairoDay(), String(title || '').slice(0, 120), String(body || '').slice(0, 500), String(riderId || '').slice(0, 40), Date.now()).run();
  await sendFcmToUser(env, u, String(title || '').slice(0, 120), String(body || '').slice(0, 500), riderId);
}

async function enforceDeviceLimit(env, u, maxSessions) {
  const rows = await env.DB.prepare('SELECT token FROM sessions WHERE u=? AND expires>? ORDER BY created DESC').bind(u, Date.now()).all();
  const list = (rows.results || []).map(r => r.token);
  const excess = list.slice(Math.max(0, (maxSessions || 4) - 1));
  for (const t of excess) await env.DB.prepare('DELETE FROM sessions WHERE token=?').bind(t).run();
}

async function issueSession(env, u, remember) {
  const token = randHex(32);
  const ttl = remember ? 7 * 24 * 60 * 60 * 1000 : 12 * 60 * 60 * 1000;
  await env.DB.prepare('INSERT INTO sessions(token,u,expires,created) VALUES(?,?,?,?)').bind(token, u, Date.now() + ttl, Date.now()).run();
  return token;
}

function pemToDer(pem) {
  const b = String(pem || '').replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const bin = atob(b);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
let _fcmTok = '', _fcmTokExp = 0;
async function fcmAccessToken(env) {
  if (_fcmTok && Date.now() < _fcmTokExp) return _fcmTok;
  const sa = JSON.parse(env.FCM_SA_JSON);
  const now = Math.floor(Date.now() / 1000);
  const enc = (o) => b64u(new TextEncoder().encode(JSON.stringify(o)));
  const unsigned = enc({ alg: 'RS256', typ: 'JWT' }) + '.' + enc({ iss: sa.client_email, scope: 'https://www.googleapis.com/auth/firebase.messaging', aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600 });
  const key = await crypto.subtle.importKey('pkcs8', pemToDer(sa.private_key), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(unsigned));
  const jwt = unsigned + '.' + b64u(sig);
  const r = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=' + jwt });
  const d = await r.json();
  if (!d.access_token) throw new Error('fcm_auth_failed');
  _fcmTok = d.access_token; _fcmTokExp = Date.now() + 50 * 60 * 1000;
  return _fcmTok;
}
async function sendFcmToUser(env, u, title, body, riderId) {
  if (!env.FCM_SA_JSON) return;
  try {
    const rows = await env.DB.prepare('SELECT token FROM push_tokens WHERE u=?').bind(u).all();
    const tokens = (rows.results || []).map(r => r.token);
    if (!tokens.length) return;
    const at = await fcmAccessToken(env);
    const proj = env.FCM_PROJECT_ID || 'pilot-dashboard-d0983';
    for (const t of tokens.slice(0, 20)) {
      const r = await fetch(`https://fcm.googleapis.com/v1/projects/${proj}/messages:send`, {
        method: 'POST', headers: { 'Authorization': 'Bearer ' + at, 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: {
          token: t,
          notification: { title: String(title || ''), body: String(body || '') },
          android: { priority: 'HIGH', notification: { sound: 'default', channel_id: 'teammh_alerts' } },
          data: { rider_id: String(riderId || ''), title: String(title || ''), body: String(body || '') },
        } }),
      });
      if (r.status === 404) await env.DB.prepare('DELETE FROM push_tokens WHERE token=?').bind(t).run();
    }
  } catch (e) {}
}

async function sendMail(env, to, subject, text) {
  if (!env.BREVO_API_KEY) return { ok: false, error: 'mail_not_configured' };
  try {
    const r = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: { 'api-key': env.BREVO_API_KEY, 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({
        sender: { email: env.MAIL_FROM || 'michealuonanayad@gmail.com', name: 'لوحة أداء الطيارين' },
        to: [{ email: to }], subject, textContent: text,
      }),
    });
    return { ok: r.ok, status: r.status };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

async function sendSms(env, to, content) {
  if (!env.BREVO_API_KEY) return { ok: false, error: 'sms_not_configured' };
  const num = String(to || '').replace(/[^0-9]/g, '');
  const intl = num.startsWith('0020') ? '+' + num.slice(2) : (num.startsWith('20') ? '+' + num : (num.startsWith('0') ? '+2' + num : '+' + num));
  try {
    const r = await fetch('https://api.brevo.com/v3/transactionalSMS/sms', {
      method: 'POST',
      headers: { 'api-key': env.BREVO_API_KEY, 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ type: 'transactional', unicodeEnabled: true, sender: 'TeamMH', recipient: intl, content }),
    });
    return { ok: r.ok, status: r.status };
  } catch (e) { return { ok: false, error: String(e) }; }
}

const codeHash = (env, code) => sha256hex((env.OTP_PEPPER || 'pd') + ':' + code);

async function makeCode(env, u, purpose, digits, ttlMs) {
  const code = randCode(digits);
  await env.DB.prepare('UPDATE codes SET used=1 WHERE u=? AND purpose=? AND used=0').bind(u, purpose).run();
  await env.DB.prepare('INSERT INTO codes(u,purpose,code_hash,expires,created) VALUES(?,?,?,?,?)')
    .bind(u, purpose, await codeHash(env, code), Date.now() + ttlMs, Date.now()).run();
  return code;
}

async function verifyCode(env, u, purpose, code) {
  const row = await env.DB.prepare('SELECT id, code_hash, expires, attempts FROM codes WHERE u=? AND purpose=? AND used=0 ORDER BY id DESC LIMIT 1').bind(u, purpose).first();
  if (!row) return 'no_code';
  if (row.expires < Date.now()) return 'expired';
  if (row.attempts >= 5) return 'locked';
  const ok = safeEqual(row.code_hash, await codeHash(env, String(code).trim()));
  if (!ok) {
    await env.DB.prepare('UPDATE codes SET attempts=attempts+1 WHERE id=?').bind(row.id).run();
    return 'wrong';
  }
  await env.DB.prepare('UPDATE codes SET used=1 WHERE id=?').bind(row.id).run();
  return 'ok';
}

const cleanContact = {
  email: (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) ? v.slice(0, 120) : '',
  phone: (v) => {
    const d = String(v).replace(/[٠-٩]/g, (c) => '٠١٢٣٤٥٦٧٨٩'.indexOf(c)).replace(/\D/g, '');
    return d.length >= 8 && d.length <= 15 ? d : '';
  },
};

// --- Supervisor chat (Micheal 24 Nov): WhatsApp-style messaging between
// admin, managers and supervisors. Stored in D1, polled from the dashboard.
const CHAT_ROLES = ['admin', 'manager', 'sup'];
async function handleChat(request, env, json, url) {
  const p = url.pathname;
  const user = await getSessionUser(env, request);
  if (!user) return json({ error: 'unauthorized' }, 401);
  if (!CHAT_ROLES.includes(user.r)) return json({ error: 'forbidden' }, 403);
  if (tabBlockedFor(await getHiddenTabs(env), 'chat', user)) return json({ error: 'tab_hidden' }, 403);

  if (p === '/api/chat/contacts' && request.method === 'GET') {
    const rows = await env.DB.prepare("SELECT u,n,r,s FROM users WHERE status='active' AND r IN ('admin','manager','sup') AND u<>? ORDER BY n").bind(user.u).all();
    const pres = await env.DB.prepare('SELECT u,ts FROM chat_presence').all();
    const seen = new Map((pres.results || []).map(x => [x.u, x.ts]));
    return json({ contacts: (rows.results || []).map(x => ({ u: x.u, n: x.n, r: x.r, s: x.s, seen: seen.get(x.u) || 0 })) });
  }

  if (p === '/api/chat/offline' && request.method === 'POST') {
    // Micheal 25 Nov: explicit "I'm gone" on logout/window close (sendBeacon).
    await env.DB.prepare('DELETE FROM chat_presence WHERE u=?').bind(user.u).run();
    return json({ ok: true });
  }

  if (p === '/api/chat/ping' && request.method === 'POST') {
    await env.DB.prepare('INSERT INTO chat_presence(u,ts) VALUES(?,?) ON CONFLICT(u) DO UPDATE SET ts=excluded.ts').bind(user.u, Date.now()).run();
    return json({ ok: true });
  }

  if (p === '/api/chat/inbox' && request.method === 'GET') {
    const msgs = await env.DB.prepare('SELECT id, from_u, to_u, body, kind, ts, read_at FROM chat_messages WHERE to_u=? OR from_u=? ORDER BY id DESC LIMIT 500').bind(user.u, user.u).all();
    const peers = new Map();
    for (const m of (msgs.results || [])) {
      const peer = m.from_u === user.u ? m.to_u : m.from_u;
      let e = peers.get(peer);
      if (!e) { e = { u: peer, last: null, unread: 0 }; peers.set(peer, e); }
      if (!e.last) e.last = { body: m.kind === 'image' ? '📷 صورة' : m.body, ts: m.ts, mine: m.from_u === user.u };
      if (m.to_u === user.u && !m.read_at) e.unread++;
    }
    const list = [...peers.values()];
    if (list.length) {
      const names = await env.DB.prepare("SELECT u,n,r,s FROM users WHERE status='active'").all();
      const byU = new Map((names.results || []).map(x => [x.u, x]));
      for (const e of list) { const x = byU.get(e.u); e.n = x ? x.n : e.u; e.r = x ? x.r : ''; e.s = x ? x.s : ''; }
    }
    list.sort((a, b) => (b.last ? b.last.ts : 0) - (a.last ? a.last.ts : 0));
    return json({ conversations: list, totalUnread: list.reduce((t, e) => t + e.unread, 0) });
  }

  if (p === '/api/chat/conversations' && request.method === 'GET') {
    // Admin (Micheal 25 Nov): auto-list every existing conversation pair with
    // its last message + time, so monitoring starts from a list, not two dropdowns.
    if (user.r !== 'admin') return json({ error: 'forbidden' }, 403);
    const msgs = await env.DB.prepare('SELECT from_u,to_u,body,kind,ts FROM chat_messages ORDER BY id DESC LIMIT 5000').all();
    const pairs = new Map();
    for (const m of (msgs.results || [])) {
      const a = m.from_u < m.to_u ? m.from_u : m.to_u;
      const b = m.from_u < m.to_u ? m.to_u : m.from_u;
      const k = a + '|' + b;
      if (!pairs.has(k)) pairs.set(k, { a, b, last: { body: m.kind === 'image' ? '📷 صورة' : String(m.body || '').slice(0, 80), ts: m.ts } });
    }
    const list = [...pairs.values()].sort((x, y) => y.last.ts - x.last.ts);
    const names = await env.DB.prepare('SELECT u,n FROM users').all();
    const byU = new Map((names.results || []).map(x => [x.u, x.n]));
    for (const e of list) { e.an = byU.get(e.a) || e.a; e.bn = byU.get(e.b) || e.b; }
    return json({ conversations: list });
  }

  if (p === '/api/chat/peek' && request.method === 'GET') {
    // Admin-only read of any pair's conversation (Micheal 24 Nov). Read-only:
    // never marks messages read.
    if (user.r !== 'admin') return json({ error: 'forbidden' }, 403);
    const a = String(url.searchParams.get('a') || '').toLowerCase().slice(0, 60);
    const b = String(url.searchParams.get('b') || '').toLowerCase().slice(0, 60);
    if (!a || !b || a === b) return json({ error: 'bad_peer' }, 400);
    const rows = await env.DB.prepare('SELECT id, from_u, body, kind, ts, read_at FROM chat_messages WHERE (from_u=? AND to_u=?) OR (from_u=? AND to_u=?) ORDER BY id ASC LIMIT 300').bind(a, b, b, a).all();
    return json({ messages: (rows.results || []).map(m => ({ id: m.id, mine: m.from_u === a, body: m.body, kind: m.kind || 'text', ts: m.ts, read: !!m.read_at })) });
  }

  if (p === '/api/chat/delete' && request.method === 'POST') {
    // Admin deletes a whole conversation between two users (Micheal 25 Nov 13683334).
    if (user.r !== 'admin') return json({ error: 'forbidden' }, 403);
    let body = null;
    try { body = await request.json(); } catch (e) {}
    const a = String((body && body.a) || '').toLowerCase().slice(0, 60);
    const b = String((body && body.b) || '').toLowerCase().slice(0, 60);
    if (!a || !b || a === b) return json({ error: 'bad_peer' }, 400);
    const r = await env.DB.prepare('DELETE FROM chat_messages WHERE (from_u=? AND to_u=?) OR (from_u=? AND to_u=?)').bind(a, b, b, a).run();
    return json({ ok: true, deleted: (r.meta && r.meta.changes) || 0 });
  }

  if (p === '/api/chat/thread' && request.method === 'GET') {
    const peer = String(url.searchParams.get('with') || '').toLowerCase().slice(0, 60);
    if (!peer || peer === user.u) return json({ error: 'bad_peer' }, 400);
    const prow = await env.DB.prepare("SELECT u,n,r,s FROM users WHERE u=? AND status='active'").bind(peer).first();
    if (!prow || !CHAT_ROLES.includes(prow.r)) return json({ error: 'bad_peer' }, 400);
    const after = parseInt(url.searchParams.get('after') || '0', 10) || 0;
    const rows = await env.DB.prepare('SELECT id, from_u, body, kind, ts, read_at FROM chat_messages WHERE id>? AND ((from_u=? AND to_u=?) OR (from_u=? AND to_u=?)) ORDER BY id ASC LIMIT 200').bind(after, user.u, peer, peer, user.u).all();
    await env.DB.prepare('UPDATE chat_messages SET read_at=? WHERE to_u=? AND from_u=? AND read_at IS NULL').bind(Date.now(), user.u, peer).run();
    return json({ peer: { u: prow.u, n: prow.n, r: prow.r, s: prow.s }, messages: (rows.results || []).map(m => ({ id: m.id, mine: m.from_u === user.u, body: m.body, kind: m.kind || 'text', ts: m.ts, read: !!m.read_at })) });
  }

  if (p === '/api/chat/send' && request.method === 'POST') {
    const wait = await rateLimit(env, 'chat:' + user.u, 30, 60000, 60000);
    if (wait) return json({ error: 'rate_limited', wait }, 429);
    let body = null;
    try { body = await request.json(); } catch (e) {}
    const peer = String(body && body.to || '').toLowerCase().slice(0, 60);
    const kind = body && body.kind === 'image' ? 'image' : 'text';
    const text = String(body && body.body || '').trim();
    if (kind === 'image') {
      // Images are small data-URLs compressed client-side, stored in D1 (free tier).
      if (!/^data:image\/(jpeg|png|webp);base64,/.test(text) || text.length > 500000) return json({ error: 'bad_image' }, 400);
    } else if (!text || text.length > 1000) return json({ error: 'bad_message' }, 400);
    if (!peer || peer === user.u) return json({ error: 'bad_message' }, 400);
    const prow = await env.DB.prepare("SELECT u FROM users WHERE u=? AND status='active' AND r IN ('admin','manager','sup')").bind(peer).first();
    if (!prow) return json({ error: 'bad_peer' }, 400);
    const ts = Date.now();
    const r = await env.DB.prepare('INSERT INTO chat_messages(from_u,to_u,body,kind,ts) VALUES(?,?,?,?,?)').bind(user.u, peer, text, kind, ts).run();
    // APK push notification for the recipient (Micheal 24 Nov); never fail the send on it.
    try { await sendFcmToUser(env, peer, '💬 ' + user.n, kind === 'image' ? '📷 صورة' : text.slice(0, 100), ''); } catch (e) {}
    return json({ ok: true, id: r.meta && r.meta.last_row_id, ts });
  }

  return null;
}

// --- Hiring requests (Micheal 24 Nov): supervisors mirror the company hiring
// form on-site; admin approval queues the desktop app to auto-submit it.
const HIRING = {
  offices: ["Team mh for Delivery","MTA","El Abtal","Top delivery","Full Speed","El Ezz","Mobasher","Zero Zero Seven","Al Alamia","el Dawlya","El Tohami","Kaf","Speedo","Stop Car","Tanta","Tanta Car","Wakeel","Wasaly","BeCool","Moga","Turbo","Ebad El rahman","Speedy","Yalla fel Sekka","Apache","Barg","Bedaya","Noot","Super Speed","Courier for delivery","MR Delivery","A3M","SOG","Rawahel","Ready","Asphalt","Makhsos","Glesco","Ayla Express","Go Delivery","El Wafaa","El Basma","Hydwing","Galaxy","WSL"],
  hireTypes: ["New Hire (تعيينات جديده)","Reactivation (إعاده تفعيل)"],
  lectureOffices: ["مكتب طلبات المعادي","مكتب طلبات المهندسين","مكتب طلبات المنصوره","مكتب طلبات التجمع","مكتب طلبات الأسكندريه","مكتب طلبات أكتوبر","مكتب طلبات الهرم","مكتب طلبات مدينه نصر","مكتب طلبات الشروق"],
  vehicles: ["Bike","Wallker","Bicycle","Car"],
  imgKeys: ['img_license_front','img_license_back','img_nid_front','img_nid_back','img_personal'],
  imgRequired: ['img_nid_front','img_nid_back','img_personal'],
};
async function handleHiring(request, env, json, url) {
  const p = url.pathname;
  const user = await getSessionUser(env, request);
  if (!user) return json({ error: 'unauthorized' }, 401);
  const isAdmin = user.r === 'admin';
  if (tabBlockedFor(await getHiddenTabs(env), 'hiring', user)) return json({ error: 'tab_hidden' }, 403);

  if (p === '/api/hiring/submit' && request.method === 'POST') {
    if (!['admin', 'manager', 'sup'].includes(user.r)) return json({ error: 'forbidden' }, 403);
    const waitH = await rateLimit(env, 'hiring:' + user.u, 10, 60 * 60 * 1000, 60 * 1000);
    if (waitH) return json({ error: 'locked', wait: waitH }, 429);
    const body = await request.json().catch(() => null);
    if (!body) return json({ error: 'missing_fields' }, 400);
    const t = (v, n) => String(v || '').trim().slice(0, n);
    const f = {
      office: HIRING.offices.includes(body.office) ? body.office : '',
      hire_type: HIRING.hireTypes.includes(body.hire_type) ? body.hire_type : '',
      sup_name: t(body.sup_name, 120),
      lecture_office: HIRING.lectureOffices.includes(body.lecture_office) ? body.lecture_office : '',
      rider_name: t(body.rider_name, 160),
      rider_phone: cleanContact.phone(body.rider_phone || ''),
      rider_nid: String(body.rider_nid || '').replace(/[٠-٩]/g, (c) => '٠١٢٣٤٥٦٧٨٩'.indexOf(c)).replace(/\D/g, '').slice(0, 14),
      license_no: t(body.license_no, 40),
      rider_addr: t(body.rider_addr, 200),
      vehicle: HIRING.vehicles.includes(body.vehicle) ? body.vehicle : '',
    };
    if (!f.office || !f.hire_type || !f.sup_name || !f.lecture_office || !f.rider_name || !f.vehicle) return json({ error: 'missing_fields' }, 400);
    if (f.rider_nid.length !== 14) return json({ error: 'invalid_nid' }, 400);
    if (!f.rider_phone) return json({ error: 'invalid_phone' }, 400);
    const imgs = body.images && typeof body.images === 'object' ? body.images : {};
    const cleanImgs = {};
    for (const k of HIRING.imgKeys) {
      const d = typeof imgs[k] === 'string' ? imgs[k] : '';
      if (!d) continue;
      if (!/^data:image\/(jpeg|png|webp);base64,/.test(d) || d.length > 500000) return json({ error: 'bad_image' }, 400);
      cleanImgs[k] = d;
    }
    for (const k of HIRING.imgRequired) if (!cleanImgs[k]) return json({ error: 'missing_image' }, 400);
    const now = Date.now();
    const ins = await env.DB.prepare("INSERT INTO hiring_requests(u,payload,status,ts,updated) VALUES(?,?,'pending',?,?)").bind(user.u, JSON.stringify(f), now, now).run();
    const rid = ins.meta.last_row_id;
    for (const k of HIRING.imgKeys) {
      if (cleanImgs[k]) await env.DB.prepare('INSERT INTO hiring_images(request_id,k,data) VALUES(?,?,?)').bind(rid, k, cleanImgs[k]).run();
    }
    try {
      const admins = await env.DB.prepare("SELECT u FROM users WHERE r='admin' AND status='active'").all();
      for (const a of admins.results || []) await sendFcmToUser(env, a.u, '📋 طلب تعيين جديد', f.rider_name + ' — ' + user.n, '');
    } catch (e) {}
    return json({ ok: true, id: rid });
  }

  if (p === '/api/hiring/list' && request.method === 'GET') {
    // Desktop heartbeat for the list header (Micheal 25 Nov): "app last seen
    // X ago, version Y" so a queued request is explainable at a glance.
    const agentRow = await env.DB.prepare("SELECT v FROM settings WHERE k='hiring_agent'").first();
    let agent = null;
    try { agent = agentRow ? JSON.parse(agentRow.v) : null; } catch (e) {}
    const rows = isAdmin
      ? await env.DB.prepare('SELECT id,u,payload,status,result,ts,updated FROM hiring_requests ORDER BY id DESC LIMIT 200').all()
      : await env.DB.prepare('SELECT id,u,payload,status,result,ts,updated FROM hiring_requests WHERE u=? ORDER BY id DESC LIMIT 100').bind(user.u).all();
    return json({ agent, items: (rows.results || []).map((r) => ({ id: r.id, u: r.u, payload: JSON.parse(r.payload), status: r.status, result: r.result, ts: r.ts, updated: r.updated })) });
  }

  if (p === '/api/hiring/item' && request.method === 'GET') {
    const id = Number(url.searchParams.get('id') || 0);
    const r = await env.DB.prepare('SELECT * FROM hiring_requests WHERE id=?').bind(id).first();
    if (!r || (!isAdmin && r.u !== user.u)) return json({ error: 'not_found' }, 404);
    const imgs = await env.DB.prepare('SELECT k,data FROM hiring_images WHERE request_id=?').bind(id).all();
    const images = {};
    for (const x of imgs.results || []) images[x.k] = x.data;
    return json({ item: { id: r.id, u: r.u, payload: JSON.parse(r.payload), status: r.status, result: r.result, ts: r.ts, updated: r.updated }, images });
  }

  if (p === '/api/hiring/approve' && request.method === 'POST') {
    if (!isAdmin) return json({ error: 'forbidden' }, 403);
    const body = await request.json().catch(() => null);
    const id = Number((body && body.id) || 0);
    const r = await env.DB.prepare("SELECT * FROM hiring_requests WHERE id=? AND status='pending'").bind(id).first();
    if (!r) return json({ error: 'not_found' }, 404);
    const payload = JSON.parse(r.payload);
    if (body && body.hire_type && HIRING.hireTypes.includes(body.hire_type)) payload.hire_type = body.hire_type;
    await env.DB.prepare("UPDATE hiring_requests SET payload=?, status='approved', updated=? WHERE id=?").bind(JSON.stringify(payload), Date.now(), id).run();
    return json({ ok: true });
  }

  if (p === '/api/hiring/reject' && request.method === 'POST') {
    if (!isAdmin) return json({ error: 'forbidden' }, 403);
    const body = await request.json().catch(() => null);
    const id = Number((body && body.id) || 0);
    const r = await env.DB.prepare("SELECT id FROM hiring_requests WHERE id=? AND status='pending'").bind(id).first();
    if (!r) return json({ error: 'not_found' }, 404);
    await env.DB.prepare("UPDATE hiring_requests SET status='rejected', updated=? WHERE id=?").bind(Date.now(), id).run();
    return json({ ok: true });
  }

  // Desktop queue: oldest approved request, claimed for 10 minutes.
  if (p === '/api/hiring/poll' && request.method === 'GET') {
    if (!isAdmin) return json({ error: 'forbidden' }, 403);
    const now = Date.now();
    // Heartbeat: the desktop reports its version on every poll.
    const pv = (url.searchParams.get('v') || '').slice(0, 20);
    await env.DB.prepare("INSERT INTO settings(k,v) VALUES('hiring_agent',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(JSON.stringify({ ts: now, v: pv })).run();
    // A claim lease expires after 6 minutes: the walk watchdog kills any run at
    // 5, so a claim older than 6 min belongs to a crashed/closed app (was 10).
    await env.DB.prepare("UPDATE hiring_requests SET status='approved',updated=? WHERE status='claimed' AND updated<?").bind(now, now - 6 * 60 * 1000).run();
    const r = await env.DB.prepare("SELECT * FROM hiring_requests WHERE status='approved' ORDER BY id LIMIT 1").first();
    if (!r) return json({ job: null });
    await env.DB.prepare("UPDATE hiring_requests SET status='claimed',updated=? WHERE id=? AND status='approved'").bind(now, r.id).run();
    const imgs = await env.DB.prepare('SELECT k,data FROM hiring_images WHERE request_id=?').bind(r.id).all();
    const images = {};
    for (const x of imgs.results || []) images[x.k] = x.data;
    return json({ job: { id: r.id, u: r.u, payload: JSON.parse(r.payload), images } });
  }

  if (p === '/api/hiring/delete' && request.method === 'POST') {
    // Micheal 25 Nov: admin can remove any uploaded request (with its images).
    if (!isAdmin) return json({ error: 'forbidden' }, 403);
    const body = await request.json().catch(() => null);
    const id = Number((body && body.id) || 0);
    const r = await env.DB.prepare('SELECT id FROM hiring_requests WHERE id=?').bind(id).first();
    if (!r) return json({ error: 'not_found' }, 404);
    await env.DB.prepare('DELETE FROM hiring_images WHERE request_id=?').bind(id).run();
    await env.DB.prepare('DELETE FROM hiring_requests WHERE id=?').bind(id).run();
    return json({ ok: true });
  }

  if (p === '/api/hiring/report' && request.method === 'POST') {
    if (!isAdmin) return json({ error: 'forbidden' }, 403);
    const body = await request.json().catch(() => null);
    const id = Number((body && body.id) || 0);
    const r = await env.DB.prepare('SELECT id FROM hiring_requests WHERE id=?').bind(id).first();
    if (!r) return json({ error: 'not_found' }, 404);
    const retry = body && body.retry === true;
    const status = retry ? 'approved' : ((body && body.ok) ? 'submitted' : 'failed');
    const result = JSON.stringify({ error: String((body && body.error) || '').slice(0, 400), detail: String((body && body.detail) || '').slice(0, 3500) });
    await env.DB.prepare('UPDATE hiring_requests SET status=?,result=?,updated=? WHERE id=?').bind(status, result, Date.now(), id).run();
    return json({ ok: true });
  }

  return null;
}

// --- Shift commands relay (Micheal 25 Nov): individual مد/فك بريك/فتح شيفت
// enqueued on the site (admin only, per-tap confirm), executed by the Windows
// desktop app on its next poll. Site checks the desktop heartbeat first and
// refuses to queue when the desktop is offline.
async function handleShiftCmd(request, env, json, url) {
  const p = url.pathname;
  const user = await getSessionUser(env, request);
  if (!user) return json({ error: 'unauthorized' }, 401);
  const isAdmin = user.r === 'admin';
  const now = Date.now();

  if (p === '/api/shiftcmd/submit' && request.method === 'POST') {
    if (!isAdmin) return json({ error: 'forbidden' }, 403);
    const body = await request.json().catch(() => null);
    const f = body && body.payload;
    if (!f || typeof f !== 'object') return json({ error: 'missing_fields' }, 400);
    const action = String(f.action || '');
    if (!['extend', 'break', 'open'].includes(action)) return json({ error: 'bad_action' }, 400);
    const riderId = String(f.rider_id || '').replace(/[^0-9]/g, '');
    const city = String(f.city || '').trim();
    if (!riderId || !city) return json({ error: 'missing_fields' }, 400);
    const payload = {
      action, rider_id: riderId, city,
      duration24: String(f.duration24 || '').slice(0, 5),
      reason: String(f.reason || '').slice(0, 60),
      vehicle: String(f.vehicle || '').slice(0, 30)
    };
    // 25 Nov: dedupe — a double-click or two admins sending the same action for the same rider
    // must not execute twice (a second مد would double the extension on the Google form).
    const dup = await env.DB.prepare("SELECT id FROM shift_commands WHERE status IN ('pending','claimed') AND payload LIKE ? AND payload LIKE ? LIMIT 1")
      .bind('%"action":"' + action + '"%', '%"rider_id":"' + riderId + '"%').first();
    if (dup) return json({ ok: true, id: dup.id, already_queued: true });
    const ins = await env.DB.prepare("INSERT INTO shift_commands(u,payload,status,ts,updated) VALUES(?,?,'pending',?,?)").bind(user.u, JSON.stringify(payload), now, now).run();
    return json({ ok: true, id: ins.meta.last_row_id });
  }

  if (p === '/api/shiftcmd/list' && request.method === 'GET') {
    if (!isAdmin) return json({ error: 'forbidden' }, 403);
    const agentRow = await env.DB.prepare("SELECT v FROM settings WHERE k='shift_agent'").first();
    let agent = null;
    try { agent = agentRow ? JSON.parse(agentRow.v) : null; } catch (e) {}
    const rows = await env.DB.prepare('SELECT id,u,payload,status,result,ts,updated FROM shift_commands ORDER BY id DESC LIMIT 50').all();
    return json({ commands: rows.results || [], agent });
  }

  if (p === '/api/shiftcmd/item' && request.method === 'GET') {
    if (!isAdmin) return json({ error: 'forbidden' }, 403);
    const id = Number(url.searchParams.get('id') || 0);
    const r = await env.DB.prepare('SELECT id,payload,status,result,ts,updated FROM shift_commands WHERE id=?').bind(id).first();
    if (!r) return json({ error: 'not_found' }, 404);
    return json({ item: r });
  }

  if (p === '/api/shiftcmd/delete' && request.method === 'POST') {
    if (!isAdmin) return json({ error: 'forbidden' }, 403);
    const body = await request.json().catch(() => null);
    const id = Number((body && body.id) || 0);
    const r = await env.DB.prepare('SELECT id,status FROM shift_commands WHERE id=?').bind(id).first();
    if (!r) return json({ error: 'not_found' }, 404);
    if (r.status === 'claimed') return json({ error: 'already_running' }, 409);
    await env.DB.prepare('DELETE FROM shift_commands WHERE id=?').bind(id).run();
    return json({ ok: true });
  }

  if (p === '/api/shiftcmd/poll' && request.method === 'GET') {
    if (!isAdmin) return json({ error: 'forbidden' }, 403);
    const pv = String(url.searchParams.get('v') || '').slice(0, 20);
    await env.DB.prepare("INSERT INTO settings(k,v) VALUES('shift_agent',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(JSON.stringify({ ts: now, v: pv })).run();
    // Recover commands claimed >6 min ago by a desktop that died mid-run.
    await env.DB.prepare("UPDATE shift_commands SET status='pending',updated=? WHERE status='claimed' AND updated<?").bind(now, now - 6 * 60 * 1000).run();
    const r = await env.DB.prepare("SELECT * FROM shift_commands WHERE status='pending' ORDER BY id LIMIT 1").first();
    if (!r) return json({ job: null });
    await env.DB.prepare("UPDATE shift_commands SET status='claimed',updated=? WHERE id=? AND status='pending'").bind(now, r.id).run();
    return json({ job: { id: r.id, payload: JSON.parse(r.payload) } });
  }

  if (p === '/api/shiftcmd/report' && request.method === 'POST') {
    if (!isAdmin) return json({ error: 'forbidden' }, 403);
    const body = await request.json().catch(() => null);
    const id = Number((body && body.id) || 0);
    const r = await env.DB.prepare('SELECT id FROM shift_commands WHERE id=?').bind(id).first();
    if (!r) return json({ error: 'not_found' }, 404);
    const status = (body && body.ok) ? 'done' : 'failed';
    const result = JSON.stringify({ error: String((body && body.error) || '').slice(0, 400), detail: String((body && body.detail) || '').slice(0, 1500) });
    await env.DB.prepare('UPDATE shift_commands SET status=?,result=?,updated=? WHERE id=?').bind(status, result, Date.now(), id).run();
    return json({ ok: true });
  }

  return null;
}

// --- Combined agent poll (Micheal 25 Nov): ONE cheap endpoint the desktop
// hits every 5s. Updates both heartbeats, recovers stale claims, and hands out
// the oldest queued job (shift commands first - live ops - then hiring).
// ?busy=1 = heartbeat only, no claim (app mid-run; keeps the site indicator
// honest during long walks).
async function handleAgentPoll(request, env, json, url) {
  const user = await getSessionUser(env, request);
  if (!user) return json({ error: 'unauthorized' }, 401);
  if (user.r !== 'admin') return json({ error: 'forbidden' }, 403);
  const now = Date.now();
  const pv = String(url.searchParams.get('v') || '').slice(0, 20);
  const hb = JSON.stringify({ ts: now, v: pv });
  await env.DB.prepare("INSERT INTO settings(k,v) VALUES('hiring_agent',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(hb).run();
  await env.DB.prepare("INSERT INTO settings(k,v) VALUES('shift_agent',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(hb).run();
  await env.DB.prepare("UPDATE shift_commands SET status='pending',updated=? WHERE status='claimed' AND updated<?").bind(now, now - 6 * 60 * 1000).run();
  await env.DB.prepare("UPDATE hiring_requests SET status='approved',updated=? WHERE status='claimed' AND updated<?").bind(now, now - 6 * 60 * 1000).run();
  if (url.searchParams.get('busy')) return json({ job: null });
  const s = await env.DB.prepare("SELECT * FROM shift_commands WHERE status='pending' ORDER BY id LIMIT 1").first();
  if (s) {
    await env.DB.prepare("UPDATE shift_commands SET status='claimed',updated=? WHERE id=? AND status='pending'").bind(now, s.id).run();
    return json({ job: { kind: 'shift', id: s.id, payload: JSON.parse(s.payload) } });
  }
  const r = await env.DB.prepare("SELECT * FROM hiring_requests WHERE status='approved' ORDER BY id LIMIT 1").first();
  if (!r) return json({ job: null });
  await env.DB.prepare("UPDATE hiring_requests SET status='claimed',updated=? WHERE id=? AND status='approved'").bind(now, r.id).run();
  const imgs = await env.DB.prepare('SELECT k,data FROM hiring_images WHERE request_id=?').bind(r.id).all();
  const images = {};
  for (const x of imgs.results || []) images[x.k] = x.data;
  return json({ job: { kind: 'hiring', id: r.id, u: r.u, payload: JSON.parse(r.payload), images } });
}

async function handleAuth(request, env, json, url) {
  const p = url.pathname;
  let body = request.method === 'POST' ? await request.json().catch(() => null) : null;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch { body = null; } }
  const profile = (u) => ({ u: u.u, n: u.n, r: u.r, s: u.s, has_email: !!u.email, has_phone: !!u.phone, email: u.email || '', phone: u.phone || '', channel: u.channel || '' });

  // --- public ---
  if (p === '/api/auth/login' && request.method === 'POST') {
    if (!body || !body.u || !body.p) return json({ error: 'missing_fields' }, 400);
    const u = String(body.u).toLowerCase().slice(0, 60);
    const wait = await rateLimit(env, 'login:' + u, 8, 10 * 60 * 1000, 60 * 1000);
    if (wait) return json({ error: 'locked', wait }, 429);
    // 25 Nov security pass: per-IP cap slows password spraying across many usernames.
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const waitIp = await rateLimit(env, 'loginip:' + ip, 30, 10 * 60 * 1000, 60 * 1000);
    if (waitIp) return json({ error: 'locked', wait: waitIp }, 429);
    const user = await env.DB.prepare('SELECT * FROM users WHERE u=?').bind(u).first();
    if (!user || user.status === 'disabled') return json({ error: 'invalid_credentials' }, 401);
    // Micheal 25 Nov: 5 failed passwords -> 30-minute timed lock (was full suspension).
    const flock = await env.DB.prepare('SELECT until FROM rl WHERE k=?').bind('flock:' + u).first();
    if (flock && flock.until > Date.now()) return json({ error: 'locked', wait: Math.ceil((flock.until - Date.now()) / 1000) }, 429);
    if (user.status === 'pending') return json({ error: 'pending_approval' }, 403);
    if (user.status === 'suspended') return json({ error: 'suspended' }, 403);
    if (!await verifyUserPassword(env, u, user.h, String(body.p))) {
      await env.DB.prepare('INSERT INTO login_fails(u,n) VALUES(?,1) ON CONFLICT(u) DO UPDATE SET n=n+1').bind(u).run();
      const f = await env.DB.prepare('SELECT n FROM login_fails WHERE u=?').bind(u).first();
      if (f && f.n >= 5) {
        await env.DB.prepare('DELETE FROM login_fails WHERE u=?').bind(u).run();
        await env.DB.prepare("INSERT INTO rl(k,n,until) VALUES(?,1,?) ON CONFLICT(k) DO UPDATE SET n=1, until=excluded.until").bind('flock:' + u, Date.now() + 30 * 60 * 1000).run();
        return json({ error: 'locked', wait: 1800 }, 429);
      }
      return json({ error: 'invalid_credentials', attempts_left: 5 - (f ? f.n : 1) }, 401);
    }
    await env.DB.prepare('DELETE FROM login_fails WHERE u=?').bind(u).run();
    await enforceDeviceLimit(env, u, 4);
    const token = await issueSession(env, u, !!body.remember);
    await env.DB.prepare('DELETE FROM rl WHERE k=?').bind('login:' + u).run();
    return json({ token, profile: profile(user) });
  }

  if (p === '/api/auth/register' && request.method === 'POST') {
    if (!body || !body.u || !body.p) return json({ error: 'missing_fields' }, 400);
    const u = String(body.u).toLowerCase().replace(/[^a-z0-9._-]/g, '').slice(0, 60);
    if (!u) return json({ error: 'invalid_username' }, 400);
    const waitR = await rateLimit(env, 'reg:' + u, 5, 10 * 60 * 1000, 60 * 1000);
    if (waitR) return json({ error: 'locked', wait: waitR }, 429);
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const waitIp = await rateLimit(env, 'regip:' + ip, 12, 60 * 60 * 1000, 60 * 1000);
    if (waitIp) return json({ error: 'locked', wait: waitIp }, 429);
    const pw = String(body.p);
    if (pw.length < 4) return json({ error: 'weak_password' }, 400);
    const email = cleanContact.email(String(body.email || '').trim());
    const phone = cleanContact.phone(body.phone || '');
    const channel = body.channel === 'whatsapp' ? 'whatsapp' : 'email';
    if (!email) return json({ error: 'invalid_email' }, 400);
    if (!phone) return json({ error: 'invalid_phone' }, 400);
    const n = (String(body.n || '').trim() || u).slice(0, 120);
    const existing = await env.DB.prepare('SELECT u, status FROM users WHERE u=?').bind(u).first();
    if (existing) return json({ error: existing.status === 'pending' ? 'already_pending' : 'username_taken' }, 409);
    await env.DB.prepare("INSERT INTO users(u,n,r,s,h,email,phone,channel,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,'pending',?,?)")
      .bind(u, n, 'sup', '', await hp2new(u, pw), email, phone, channel, Date.now(), Date.now()).run();
    return json({ ok: true });
  }

  if (p === '/api/auth/activate' && request.method === 'POST') {
    if (!body || !body.u || !body.code) return json({ error: 'missing_fields' }, 400);
    const u = String(body.u).toLowerCase().slice(0, 60);
    const wait = await rateLimit(env, 'act:' + u, 10, 10 * 60 * 1000, 60 * 1000);
    if (wait) return json({ error: 'locked', wait }, 429);
    const user = await env.DB.prepare('SELECT * FROM users WHERE u=?').bind(u).first();
    if (!user) return json({ error: 'user_not_found' }, 404);
    if (user.status === 'active') return json({ error: 'already_active' }, 409);
    const chk = await verifyCode(env, u, 'activate', body.code);
    if (chk !== 'ok') return json({ error: chk === 'expired' ? 'code_expired' : 'invalid_code' }, 401);
    const email = cleanContact.email(String(body.email || '').trim());
    const phone = cleanContact.phone(body.phone || '');
    const channel = body.channel === 'whatsapp' ? 'whatsapp' : 'email';
    if (!email) return json({ error: 'invalid_email' }, 400);
    await env.DB.prepare('UPDATE users SET email=?, phone=?, channel=?, status=?, updated_at=? WHERE u=?')
      .bind(email, phone, channel, 'active', Date.now(), u).run();
    const mail = await sendMail(env, email, 'تم تفعيل حسابك ✅',
      'أهلًا ' + user.n + ',\n\nتم تفعيل حسابك في لوحة أداء الطيارين بنجاح.\nاسم المستخدم: ' + u +
      '\nرقم الواتساب المسجل: ' + (phone || '—') +
      '\nأكواد الدخول هتوصلك على: ' + (channel === 'whatsapp' ? 'الواتساب' : 'الجيميل') +
      '\n\nلو مش انت اللي عملت كده، كلم الأدمن فورًا.');
    return json({ ok: true, emailed: mail.ok });
  }

  if (p === '/api/auth/otp/request' && request.method === 'POST') {
    if (!body || !body.u) return json({ error: 'missing_fields' }, 400);
    const u = String(body.u).toLowerCase().slice(0, 60);
    const wait = await rateLimit(env, 'otp:' + u, 5, 10 * 60 * 1000, 60 * 1000);
    if (wait) return json({ error: 'locked', wait }, 429);
    const user = await env.DB.prepare('SELECT * FROM users WHERE u=?').bind(u).first();
    if (!user || user.status === 'disabled') return json({ error: 'invalid_credentials' }, 401);
    if (user.status === 'pending') return json({ error: 'pending_approval' }, 403);
    if (!user.email) return json({ error: 'no_email' }, 400);
    const code = await makeCode(env, u, 'login', 6, 10 * 60 * 1000);
    const mail = await sendMail(env, user.email, 'كود الدخول: ' + code,
      'أهلًا ' + user.n + ',\n\nكود الدخول بتاعك: ' + code + '\nصالح لمدة 10 دقائق.\n\nلو انت مش اللي طلبته، تجاهل الرسالة وكلم الأدمن.');
    if (!mail.ok) return json({ error: 'mail_failed' }, 503);
    return json({ ok: true, email: user.email.replace(/^(.{2}).+(@.+)$/, '$1***$2') });
  }

  if (p === '/api/auth/otp/verify' && request.method === 'POST') {
    if (!body || !body.u || !body.code) return json({ error: 'missing_fields' }, 400);
    const u = String(body.u).toLowerCase().slice(0, 60);
    const user = await env.DB.prepare('SELECT * FROM users WHERE u=?').bind(u).first();
    if (!user || user.status === 'disabled') return json({ error: 'invalid_credentials' }, 401);
    if (user.status === 'pending') return json({ error: 'pending_approval' }, 403);
    const chk = await verifyCode(env, u, 'login', body.code);
    if (chk !== 'ok') return json({ error: chk === 'expired' ? 'code_expired' : 'invalid_code' }, 401);
    const token = await issueSession(env, u, !!body.remember);
    return json({ token, profile: profile(user) });
  }

  if (p === '/api/auth/forgot' && request.method === 'POST') {
    if (!body || !body.u) return json({ error: 'missing_fields' }, 400);
    const u = String(body.u).toLowerCase().slice(0, 60);
    // 25 Nov: was 3/hour + 30-min lock while the UI said 'wait a minute' (Micheal 12590877). New key drops old stuck locks.
    const wait = await rateLimit(env, 'forgot2:' + u, 5, 15 * 60 * 1000, 2 * 60 * 1000);
    if (wait) return json({ error: 'locked', wait }, 429);
    const user = await env.DB.prepare('SELECT * FROM users WHERE u=?').bind(u).first();
    if (user && user.status !== 'disabled' && (user.email || user.phone)) {
      const code = await makeCode(env, u, 'reset', 8, 60 * 60 * 1000);
      const text = 'أهلًا ' + user.n + ',\n\nكود إعادة تعيين كلمة المرور: ' + code + '\nصالح لمدة ساعة.\n\nلو مش انت اللي طلبت، كلم الأدمن فورًا.';
      let sent = false, via = '';
      // Email first for EVERY channel: the worker has no WhatsApp sender, and a 'whatsapp' channel used to fall straight to Brevo SMS, which never arrived.
      if (user.email) {
        const mail = await sendMail(env, user.email, 'كود إعادة تعيين كلمة المرور', text);
        sent = mail.ok; via = 'email';
      }
      if (!sent && user.phone) {
        const sm = await sendSms(env, user.phone, 'كود إعادة تعيين كلمة المرور: ' + code + ' (صالح لمدة ساعة)');
        sent = sm.ok; via = 'sms';
      }
      if (!sent && user.email && via !== 'email') {
        const mail = await sendMail(env, user.email, 'كود إعادة تعيين كلمة المرور', text);
        sent = mail.ok; via = 'email';
      }
      if (sent) return json({ ok: true, self: true, via, hint: via === 'email' ? user.email.replace(/^(.{2}).+(@.+)$/, '$1***$2') : ('*****' + String(user.phone).replace(/[^0-9]/g, '').slice(-4)) });
    }
    if (user) {
      const existing = await env.DB.prepare("SELECT id FROM recoveries WHERE u=? AND status='pending'").bind(u).first();
      if (!existing) await env.DB.prepare('INSERT INTO recoveries(u,created) VALUES(?,?)').bind(u, Date.now()).run();
    }
    return json({ ok: true });
  }

  if (p === '/api/auth/reset' && request.method === 'POST') {
    if (!body || !body.u || !body.code || !body.p) return json({ error: 'missing_fields' }, 400);
    const u = String(body.u).toLowerCase().slice(0, 60);
    const p2 = String(body.p);
    if (p2.length < 4) return json({ error: 'weak_password' }, 400);
    const chk = await verifyCode(env, u, 'reset', body.code);
    if (chk !== 'ok') return json({ error: chk === 'expired' ? 'code_expired' : 'invalid_code' }, 401);
    await env.DB.prepare('UPDATE users SET h=?, updated_at=? WHERE u=?').bind(await hp2new(u, p2), Date.now(), u).run();
    await env.DB.prepare('DELETE FROM sessions WHERE u=?').bind(u).run();
    return json({ ok: true });
  }

  if (p === '/api/auth/profile/photo' && request.method === 'POST') {
    const user = await getSessionUser(env, request);
    if (!user) return json({ error: 'unauthorized' }, 401);
    const photo = String(body && body.photo || '');
    if (!/^data:image\/(jpeg|png);base64,[A-Za-z0-9+/=]+$/.test(photo) || photo.length > 180000) return json({ error: 'invalid_photo' }, 400);
    await env.DB.prepare('UPDATE users SET photo=?, updated_at=? WHERE u=?').bind(photo, Date.now(), user.u).run();
    return json({ ok: true });
  }

  if (p === '/api/auth/profile/photo' && request.method === 'GET') {
    const user = await getSessionUser(env, request);
    if (!user) return json({ error: 'unauthorized' }, 401);
    const q = String(url.searchParams.get('u') || '').toLowerCase().slice(0, 60);
    const target = (q && ['admin', 'manager'].includes(user.r)) ? q : user.u;
    const row = await env.DB.prepare('SELECT photo FROM users WHERE u=?').bind(target).first();
    return json({ photo: (row && row.photo) || '' });
  }

  if (p === '/api/auth/viewer-access' && request.method === 'GET') {
    const user = await getSessionUser(env, request);
    if (!user) return json({ error: 'unauthorized' }, 401);
    const q = String(url.searchParams.get('u') || '').toLowerCase().slice(0, 60);
    const target = (q && (user.r === 'admin' || user.r === 'manager')) ? q : user.u;
    const rows = await env.DB.prepare('SELECT sup_name FROM viewer_access WHERE viewer_u=? ORDER BY sup_name').bind(target).all();
    return json({ sups: (rows.results || []).map(r => r.sup_name) });
  }

  if (p === '/api/auth/complete-contact' && request.method === 'POST') {
    const user = await getSessionUser(env, request);
    if (!user) return json({ error: 'unauthorized' }, 401);
    const email = cleanContact.email(String(body && body.email || '').trim());
    const phone = cleanContact.phone(body && body.phone || '');
    const channel = body && body.channel === 'whatsapp' ? 'whatsapp' : 'email';
    if (!email) return json({ error: 'invalid_email' }, 400);
    if (!phone) return json({ error: 'invalid_phone' }, 400);
    await env.DB.prepare('UPDATE users SET email=?, phone=?, channel=?, updated_at=? WHERE u=?').bind(email, phone, channel, Date.now(), user.u).run();
    return json({ ok: true });
  }

  if (p === '/api/auth/me' && request.method === 'GET') {
    const user = await getSessionUser(env, request);
    if (!user) return json({ error: 'unauthorized' }, 401);
    return json({ profile: profile(user) });
  }

  if (p === '/api/auth/logout' && request.method === 'POST') {
    const user = await getSessionUser(env, request);
    if (user) {
      await env.DB.prepare('DELETE FROM sessions WHERE token=?').bind(user.token).run();
      // Micheal 25 Nov: logging out must drop chat presence immediately.
      await env.DB.prepare('DELETE FROM chat_presence WHERE u=?').bind(user.u).run();
    }
    return json({ ok: true });
  }

  if (p === '/api/auth/audit' && request.method === 'POST') {
    const user = await getSessionUser(env, request);
    if (!user) return json({ error: 'unauthorized' }, 401);
    await env.DB.prepare('INSERT INTO audit(u,n,r,ip,ts) VALUES(?,?,?,?,?)')
      .bind(user.u, user.n, user.r, request.headers.get('CF-Connecting-IP') || '', Date.now()).run();
    if (env.LOGIN_AUDIT_URL) {
      try {
        await fetch(env.LOGIN_AUDIT_URL, {
          method: 'POST', headers: { 'Content-Type': 'text/plain;charset=utf-8' },
          body: JSON.stringify({ username: user.u, displayName: user.n, role: user.r }),
        });
      } catch {}
    }
    return json({ ok: true });
  }

  // --- one-time seed (requires SEED_TOKEN secret; remove secret after use) ---
  if (p === '/api/auth/seed' && request.method === 'POST') {
    if (!env.SEED_TOKEN || !safeEqual(request.headers.get('Authorization') || '', 'Bearer ' + env.SEED_TOKEN)) return json({ error: 'unauthorized' }, 401);
    if (!body || !Array.isArray(body.users) || body.users.length > 1000) return json({ error: 'invalid_body' }, 400);
    let n = 0;
    const stmts = [];
    for (const x of body.users) {
      if (!x || !x.u || !x.h) continue;
      stmts.push(env.DB.prepare('INSERT INTO users(u,n,r,s,h,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(u) DO UPDATE SET n=excluded.n, r=excluded.r, s=excluded.s, h=excluded.h, updated_at=excluded.updated_at')
        .bind(String(x.u).toLowerCase(), String(x.n || ''), String(x.r || 'sup'), String(x.s || ''), String(x.h), 'active', Date.now(), Date.now()));
      n++;
      if (stmts.length >= 50) { await env.DB.batch(stmts.splice(0)); }
    }
    if (stmts.length) await env.DB.batch(stmts);
    return json({ ok: true, count: n });
  }

  // --- admin ---
  if (p.startsWith('/api/auth/admin/')) {
    const admin = await getSessionUser(env, request);
    if (!admin || admin.r !== 'admin') return json({ error: 'unauthorized' }, 401);

    if (p === '/api/auth/admin/users' && request.method === 'GET') {
      const rows = await env.DB.prepare('SELECT u,n,r,s,email,phone,channel,status FROM users ORDER BY r, u').all();
      return json({ users: rows.results || [] });
    }

    if (p === '/api/auth/admin/users' && request.method === 'POST') {
      if (!body || !body.u || !body.r) return json({ error: 'missing_fields' }, 400);
      const u = String(body.u).toLowerCase().replace(/[^a-z0-9._-]/g, '').slice(0, 60);
      const r = ['admin', 'manager', 'sup', 'monitor', 'viewer'].includes(body.r) ? body.r : 'sup';
      const s = ['admin', 'monitor'].includes(r) ? '' : String(body.s || '').slice(0, 120);
      const n = String(body.n || u).slice(0, 120);
      if (!u) return json({ error: 'invalid_username' }, 400);
      const rename = body.rename ? String(body.rename).toLowerCase() : null;
      const existing = await env.DB.prepare('SELECT u FROM users WHERE u=?').bind(u).first();
      if (rename) {
        if (rename !== u) {
          if (!body.p) return json({ error: 'password_required_for_rename' }, 400);
          if (existing) return json({ error: 'username_taken' }, 409);
          await env.DB.prepare('UPDATE users SET u=?, n=?, r=?, s=?, h=?, updated_at=? WHERE u=?')
            .bind(u, n, r, s, await hp2new(u, String(body.p)), Date.now(), rename).run();
          await env.DB.prepare('UPDATE sessions SET u=? WHERE u=?').bind(u, rename).run();
          return json({ ok: true });
        }
        if (!existing) return json({ error: 'not_found' }, 404);
        if (body.p) await env.DB.prepare('UPDATE users SET n=?, r=?, s=?, h=?, updated_at=? WHERE u=?').bind(n, r, s, await hp2new(u, String(body.p)), Date.now(), u).run();
        else await env.DB.prepare('UPDATE users SET n=?, r=?, s=?, updated_at=? WHERE u=?').bind(n, r, s, Date.now(), u).run();
        return json({ ok: true });
      }
      if (existing) {
        if (body.p) await env.DB.prepare('UPDATE users SET n=?, r=?, s=?, h=?, updated_at=? WHERE u=?').bind(n, r, s, await hp2new(u, String(body.p)), Date.now(), u).run();
        else await env.DB.prepare('UPDATE users SET n=?, r=?, s=?, updated_at=? WHERE u=?').bind(n, r, s, Date.now(), u).run();
        return json({ ok: true });
      }
      const p2 = body.p ? String(body.p) : randPassword();
      await env.DB.prepare('INSERT INTO users(u,n,r,s,h,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)')
        .bind(u, n, r, s, await hp2new(u, p2), 'active', Date.now(), Date.now()).run();
      return json({ ok: true, password: body.p ? undefined : p2 });
    }

    if (p === '/api/auth/admin/users/delete' && request.method === 'POST') {
      if (!body || !body.u) return json({ error: 'missing_fields' }, 400);
      const u = String(body.u).toLowerCase();
      const target = await env.DB.prepare('SELECT r FROM users WHERE u=?').bind(u).first();
      if (!target) return json({ error: 'not_found' }, 404);
      if (target.r === 'admin') {
        const c = await env.DB.prepare("SELECT COUNT(*) c FROM users WHERE r='admin'").first();
        if (c.c < 2) return json({ error: 'last_admin' }, 400);
      }
      await env.DB.prepare('DELETE FROM users WHERE u=?').bind(u).run();
      await env.DB.prepare('DELETE FROM sessions WHERE u=?').bind(u).run();
      return json({ ok: true });
    }

    if (p === '/api/auth/admin/viewer-access' && request.method === 'POST') {
      const u2 = String(body && body.u || '').toLowerCase();
      if (!u2 || !Array.isArray(body.sups)) return json({ error: 'missing_fields' }, 400);
      const t = await env.DB.prepare('SELECT r FROM users WHERE u=?').bind(u2).first();
      if (!t) return json({ error: 'not_found' }, 404);
      const sups = [...new Set(body.sups.map(v => String(v).trim().slice(0, 120)).filter(Boolean))].slice(0, 100);
      await env.DB.prepare('DELETE FROM viewer_access WHERE viewer_u=?').bind(u2).run();
      for (const n of sups) await env.DB.prepare('INSERT INTO viewer_access(viewer_u,sup_name) VALUES(?,?)').bind(u2, n).run();
      return json({ ok: true, count: sups.length });
    }

    if (p === '/api/auth/admin/users/reactivate' && request.method === 'POST') {
      const u2 = String(body && body.u || '').toLowerCase();
      if (!u2) return json({ error: 'missing_fields' }, 400);
      await env.DB.prepare("UPDATE users SET status='active', updated_at=? WHERE u=?").bind(Date.now(), u2).run();
      await env.DB.prepare('DELETE FROM login_fails WHERE u=?').bind(u2).run();
      return json({ ok: true });
    }

    if (p === '/api/auth/admin/invite' && request.method === 'POST') {
      if (!body || !body.u) return json({ error: 'missing_fields' }, 400);
      const u = String(body.u).toLowerCase();
      const user = await env.DB.prepare('SELECT u FROM users WHERE u=?').bind(u).first();
      if (!user) return json({ error: 'not_found' }, 404);
      const code = await makeCode(env, u, 'activate', 8, 7 * 24 * 60 * 60 * 1000);
      return json({ ok: true, code });
    }

    if (p === '/api/auth/admin/registrations' && request.method === 'GET') {
      const rows = await env.DB.prepare("SELECT u,n,email,phone,channel,created_at FROM users WHERE status='pending' ORDER BY created_at DESC LIMIT 50").all();
      return json({ items: rows.results || [] });
    }

    if (p === '/api/auth/admin/registrations/approve' && request.method === 'POST') {
      if (!body || !body.u) return json({ error: 'missing_fields' }, 400);
      const u = String(body.u).toLowerCase().slice(0, 60);
      const user = await env.DB.prepare("SELECT * FROM users WHERE u=? AND status='pending'").bind(u).first();
      if (!user) return json({ error: 'not_found' }, 404);
      const r = ['admin', 'manager', 'sup', 'monitor', 'viewer'].includes(body.r) ? body.r : 'sup';
      const s = ['admin', 'monitor', 'viewer'].includes(r) ? '' : String(body.s || '').slice(0, 120);
      if (!['admin', 'monitor', 'viewer'].includes(r) && !s) return json({ error: 'missing_fields' }, 400);
      await env.DB.prepare("UPDATE users SET r=?, s=?, status='active', updated_at=? WHERE u=?").bind(r, s, Date.now(), u).run();
      if (user.email) {
        await sendMail(env, user.email, 'تمت الموافقة على حسابك ✅',
          'أهلًا ' + user.n + ',\n\nالأدمن وافق على حسابك في لوحة أداء الطيارين.\nاسم المستخدم: ' + u + '\nسجّل دخولك دلوقتي بكلمة المرور اللي سجّلت بيها.\n\nلو مش انت اللي سجّلت، كلم الأدمن فورًا.');
      }
      return json({ ok: true });
    }

    if (p === '/api/auth/admin/registrations/reject' && request.method === 'POST') {
      if (!body || !body.u) return json({ error: 'missing_fields' }, 400);
      const u = String(body.u).toLowerCase().slice(0, 60);
      await env.DB.prepare("DELETE FROM users WHERE u=? AND status='pending'").bind(u).run();
      return json({ ok: true });
    }

    if (p === '/api/auth/admin/recoveries' && request.method === 'GET') {
      const rows = await env.DB.prepare("SELECT rc.id, rc.u, rc.created, us.n FROM recoveries rc LEFT JOIN users us ON us.u=rc.u WHERE rc.status='pending' ORDER BY rc.id DESC LIMIT 50").all();
      return json({ items: rows.results || [] });
    }

    if (p === '/api/auth/admin/recoveries/approve' && request.method === 'POST') {
      if (!body || !body.id) return json({ error: 'missing_fields' }, 400);
      const rec = await env.DB.prepare("SELECT * FROM recoveries WHERE id=? AND status='pending'").bind(Number(body.id)).first();
      if (!rec) return json({ error: 'not_found' }, 404);
      const user = await env.DB.prepare('SELECT * FROM users WHERE u=?').bind(rec.u).first();
      if (!user) return json({ error: 'not_found' }, 404);
      const code = await makeCode(env, rec.u, 'reset', 8, 24 * 60 * 60 * 1000);
      await env.DB.prepare("UPDATE recoveries SET status='approved', resolved=? WHERE id=?").bind(Date.now(), rec.id).run();
      let emailed = false;
      if (user.email) {
        const mail = await sendMail(env, user.email, 'كود إعادة تعيين كلمة المرور',
          'أهلًا ' + user.n + ',\n\nالأدمن وافق على طلبك. كود إعادة تعيين كلمة المرور: ' + code + '\nصالح لمدة 24 ساعة.\n\nلو مش انت اللي طلبت، كلم الأدمن فورًا.');
        emailed = mail.ok;
      }
      return json({ ok: true, code, emailed, phone: user.phone || '' });
    }

    if (p === '/api/auth/admin/recoveries/reject' && request.method === 'POST') {
      if (!body || !body.id) return json({ error: 'missing_fields' }, 400);
      await env.DB.prepare("UPDATE recoveries SET status='rejected', resolved=? WHERE id=?").bind(Date.now(), Number(body.id)).run();
      return json({ ok: true });
    }

    return json({ error: 'not_found' }, 404);
  }

  return null; // not an auth route
}

/* ---------------- main fetch ---------------- */

const LIVE_SHEET_ID = '1OLvK2_Wi7k8jTa9K1FdLkNjQwpMD5ntMsG_pC8woTlk';
const LIVE_GID = '524668708';

function parseCsv(text) {
  const rows = [];
  let row = [], field = '', inQ = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQ) {
      if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else inQ = false; }
      else field += c;
    } else if (c === '"') inQ = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field); field = '';
      if (row.some(v => v !== '')) rows.push(row);
      row = [];
    } else field += c;
  }
  row.push(field);
  if (row.some(v => v !== '')) rows.push(row);
  return rows;
}

async function runStatusCron(env) {
  await ensureSchema(env);
  const res = await fetch(`https://docs.google.com/spreadsheets/d/${LIVE_SHEET_ID}/gviz/tq?tqx=out:csv&gid=${LIVE_GID}&headers=1&_=${Date.now()}`);
  if (!res.ok) return;
  const rows = parseCsv(await res.text()).slice(1);
  const current = new Map();
  for (const r of rows) {
    const id = String(r[2] || '').trim();
    if (!id || !/^[0-9A-Za-z-]{3,20}$/.test(id)) continue;
    current.set(id, {
      name: String(r[3] || '').trim().slice(0, 80),
      state: String(r[14] || '').trim().slice(0, 60),
      sup: String(r[16] || '').trim().slice(0, 80),
    });
  }
  const prevRows = await env.DB.prepare('SELECT rider_id,name,state,sup FROM rider_states').all();
  const prev = new Map((prevRows.results || []).map(r => [r.rider_id, { state: r.state, name: r.name, sup: r.sup }]));
  const seeded = prev.size > 0;
  const stmts = [];
  const changed = [];
  for (const [id, cur] of current) {
    const old = prev.get(id);
    if (old && old.state === cur.state && old.name === cur.name && old.sup === cur.sup) continue; // unchanged: no write
    stmts.push(env.DB.prepare('INSERT INTO rider_states(rider_id,name,state,sup,updated) VALUES(?,?,?,?,?) ON CONFLICT(rider_id) DO UPDATE SET name=excluded.name, state=excluded.state, sup=excluded.sup, updated=excluded.updated')
      .bind(id, cur.name, cur.state, cur.sup, Date.now()));
    changed.push([id, cur, old]);
  }
  // riders that vanished from the sheet: drop their state rows
  const gone = [];
  for (const id of prev.keys()) if (!current.has(id)) gone.push(env.DB.prepare('DELETE FROM rider_states WHERE rider_id=?').bind(id));
  if (gone.length) stmts.push(...gone);
  if (stmts.length) await env.DB.batch(stmts);
  if (!seeded) return; // first run seeds state without notifying
  for (const [id, cur, old] of changed) {
    const oldState = old ? old.state : undefined;
    if (oldState === undefined || oldState === cur.state || !cur.state) continue;
    const targets = new Map();
    if (cur.sup) {
      let supRows = await env.DB.prepare("SELECT u FROM users WHERE status='active' AND (n=? OR u=?)").bind(cur.sup, cur.sup.toLowerCase()).all();
      if (!(supRows.results || []).length) supRows = await env.DB.prepare("SELECT u FROM users WHERE status='active' AND n LIKE ?").bind('%' + cur.sup.replace(/%/g, '') + '%').all();
      for (const t of (supRows.results || [])) targets.set(t.u, 1);
    }
    for (const u of targets.keys()) {
      await insertNotification(env, u, 'تغيير حالة مندوب', `${cur.name}: من "${oldState || 'بدون حالة'}" إلى "${cur.state}"`, id);
    }
  }
}

// team_mh flag: form actions (مد/فك البريك/إجراء يدوي) restricted to admin until Micheal asks to expose them (flip with index.html const)
const FORM_ACTIONS_ADMIN_ONLY = true;

const GOOGLE_FORM_IDS = {
  alex: '1FAIpQLSffSwyTh0w4AYjTU9AG-kj-0UfJHcSTSYnR1DrWJ_h8iPYm3Q',
  general: '1FAIpQLSekxaUQPgiWq-Y_IPfsTx7wTANA324a2JklFJZ_Gxg9CGPaKA'
};
function buildFormJob(body) {
  const action = String(body.action || '');
  const riderId = String(body.rider_id || '').replace(/[^0-9]/g, '');
  const city = String(body.city || '').trim();
  const duration = String(body.duration || '').trim();
  const reason = String(body.reason || '').trim();
  const zone = String(body.zone || '').trim();
  if (!['extend', 'break', 'open'].includes(action)) return { error: 'bad_action' };
  if (!riderId) return { error: 'bad_rider' };
  if (!city) return { error: 'bad_city' };
  if (action === 'extend' && !duration) return { error: 'bad_duration' };
  const isAlex = city === '\u0627\u0644\u0625\u0633\u0643\u0646\u062f\u0631\u064a\u0629';
  if (action === 'break' && isAlex && !reason) return { error: 'bad_reason' };
  const FORM_ZONE_VALUES = { '\u0627\u0644\u063a\u0631\u062f\u0642\u0629': '\u0627\u0644\u063a\u0631\u0627\u062f\u0642\u0647' };
  const cityVal = FORM_ZONE_VALUES[zone] || FORM_ZONE_VALUES[city] || zone || city;
  let fields, pageHistory;
  if (isAlex) {
    const m = action === 'break' ? ['','0','00',''] : duration.match(/^(\d{1,2}):(\d{2})$/) || duration.match(/(\d{1,2}):(\d{2})\s*(\u0627\u0644\u0641\u062c\u0631|\u0627\u0644\u0635\u0628\u062d|\u0627\u0644\u0636\u0647\u0631|\u0627\u0644\u0639\u0635\u0631|\u0628\u0644\u064a\u0644)/);
    if (!m) return { error: 'bad_duration_format' };
    let hh = parseInt(m[1], 10); if (hh > 23 || +m[2] > 59) return { error: 'bad_duration_format' };
    if (m[3] === '\u0627\u0644\u0636\u0647\u0631' || m[3] === '\u0627\u0644\u0639\u0635\u0631') { if (hh !== 12) hh += 12; }
    if (m[3] === '\u0628\u0644\u064a\u0644') { hh = hh === 12 ? 0 : hh + 12; }
    if (action === 'extend') {
      fields = { 'entry.1976663790': '\u0634\u064a\u0641\u062a\u0627\u062a \u0627\u0644\u0637\u064a\u0627\u0631\u064a\u0646', 'entry.186608000': riderId, 'entry.2117629487': '\u062a\u0632\u0648\u064a\u062f\u0627\u062a \u0634\u064a\u0641\u062a\u0627\u062a \u0627\u0644\u0637\u064a\u0627\u0631\u064a\u0646', 'entry.536642639_hour': String(hh), 'entry.536642639_minute': m[2] };
      pageHistory = '0,1,2';
    } else {
      fields = { 'entry.1976663790': '\u0634\u064a\u0641\u062a\u0627\u062a \u0627\u0644\u0637\u064a\u0627\u0631\u064a\u0646', 'entry.186608000': riderId, 'entry.2117629487': '\u0627\u0644\u0628\u0631\u064a\u0643\u0627\u062a', 'entry.1290442973': '\u0641\u0643 \u0628\u0631\u064a\u0643', 'entry.1831411232': reason };
      pageHistory = '0,1,15';
    }
  } else if (action === 'extend') {
    fields = { 'entry.302135773': '\u0634\u064a\u0641\u062a\u0627\u062a \u0627\u0644\u0637\u064a\u0627\u0631\u064a\u0646', 'entry.1941659317': '\u062a\u0632\u0648\u064a\u062f\u0627\u062a \u0634\u064a\u0641\u062a\u0627\u062a \u0627\u0644\u0637\u064a\u0627\u0631\u064a\u0646', 'entry.1552166535': duration, 'entry.1026285494': riderId, 'entry.1529435164': cityVal };
    pageHistory = '0,1,2';
  } else {
    fields = { 'entry.302135773': '\u0634\u064a\u0641\u062a\u0627\u062a \u0627\u0644\u0637\u064a\u0627\u0631\u064a\u0646', 'entry.1941659317': '\u0641\u0643 \u0628\u0631\u064a\u0643', 'entry.264752225': riderId, 'entry.1551386634': cityVal };
    pageHistory = '0,1,6';
  }
  return { action, riderId, city, duration, reason, isAlex, fields, pageHistory, formId: isAlex ? GOOGLE_FORM_IDS.alex : GOOGLE_FORM_IDS.general };
}
function buildPrefillUrl(formId, fields) {
  const qs = Object.keys(fields).map(k => encodeURIComponent(k) + '=' + encodeURIComponent(fields[k])).join('&');
  return 'https://docs.google.com/forms/u/0/d/e/' + formId + '/viewform?usp=pp_url&' + qs;
}

// Worker-direct form walk (fallback egress when the Apps Script relay is held).
// Port of relay v8: dynamic multi-page walk, phone-like headers, human pacing.
const WALK_UA = 'Mozilla/5.0 (Linux; Android 13; 2109119DG) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36';
function walkHiddens(html) {
  const o = {}; const re = /<input type="hidden" name="([^"]+)" value="([^"]*)"/g; let m;
  while ((m = re.exec(html))) o[m[1]] = m[2].replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&#39;/g, "'");
  return o;
}
function walkVisible(html, base) {
  return html.indexOf('name="' + base + '"') >= 0
    || html.indexOf(base + '_sentinel') >= 0
    || html.indexOf(base + '_hour') >= 0
    || html.indexOf(base + '_minute') >= 0;
}
const walkSleep = () => new Promise(r => setTimeout(r, 900 + Math.floor(Math.random() * 800)));
async function walkFormDirect({ formId, cookie, email, fields, probe }) {
  const base = 'https://docs.google.com/forms/u/0/d/e/' + formId + '/';
  const headers = {
    'Cookie': cookie,
    'User-Agent': WALK_UA,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'ar-EG,ar;q=0.9,en;q=0.7',
    'Origin': 'https://docs.google.com',
    'Referer': base + 'viewform',
    'X-Requested-With': 'mark.via.gp'
  };
  const dead = (status, html) => status === 401 || status === 403 || /accounts\.google\.com\/(v3\/signin|ServiceLogin)/.test(html || '');
  const post = (data) => fetch(base + 'formResponse', { method: 'POST', headers: Object.assign({}, headers, { 'Content-Type': 'application/x-www-form-urlencoded' }), body: new URLSearchParams(data).toString(), redirect: 'manual' });
  const vf = await fetch(base + 'viewform', { headers });
  let html = await vf.text();
  if (dead(vf.status, html)) return { error: 'auth_expired', status: vf.status };
  let H = walkHiddens(html);
  if (!H.fbzx) return { error: 'fbzx_not_found', status: vf.status };
  const allKeys = Object.keys(fields);
  const baseOf = (k) => k.replace(/_(?:hour|minute)$/, '');
  const trail = [];
  for (let step = 0; step < 12; step++) {
    const here = {};
    allKeys.forEach(k => { if (walkVisible(html, baseOf(k))) here[k] = fields[k]; });
    const remaining = allKeys.filter(k => here[k] === undefined);
    const last = remaining.length === 0;
    const d = Object.assign({}, H, here, { dlut: String(Date.now()) });
    if (step === 0) d.emailAddress = email;
    if (last) {
      if (probe) return { ok: true, probe: true, reached: H.pageHistory || '', trail, engine: 'direct' };
      d.submissionTimestamp = String(Date.now());
      delete d['continue'];
      await walkSleep();
      const fr = await fetch(base + 'formResponse', { method: 'POST', headers: Object.assign({}, headers, { 'Content-Type': 'application/x-www-form-urlencoded' }), body: new URLSearchParams(d).toString(), redirect: 'follow' });
      const fHtml = await fr.text();
      if (dead(fr.status, fHtml)) return { error: 'auth_expired', status: fr.status, step, engine: 'direct' };
      const confirmed = fr.status === 200 && /response has been recorded|\u062a\u0645 \u062a\u0633\u062c\u064a\u0644|\u062a\u0645 \u062d\u0641\u0638|\u0625\u0631\u0633\u0627\u0644 \u0631\u062f \u0622\u062e\u0631|submit another response/i.test(fHtml);
      return confirmed ? { ok: true, status: fr.status, trail, engine: 'direct' } : { error: 'submission_unconfirmed', status: fr.status, step, len: fHtml.length, trail, engine: 'direct' };
    }
    d.continue = '1';
    await walkSleep();
    const resp = await post(d);
    const status = resp.status; html = await resp.text();
    if (dead(status, html)) return { error: 'auth_expired', status, step, engine: 'direct' };
    if (status !== 200) return { error: 'nav_failed', step, status, trail, engine: 'direct' };
    const Hn = walkHiddens(html);
    if (!Hn.pageHistory || Hn.pageHistory === H.pageHistory) return { error: 'nav_failed', step, status, detail: 'did_not_advance', pageHistory: Hn.pageHistory || '', trail, engine: 'direct' };
    trail.push(Hn.pageHistory);
    H = Hn;
  }
  return { error: 'too_many_pages', trail, engine: 'direct' };
}

export default {
  async fetch(request, env, ctx) {
    bumpUsage(env, ctx);
    const origin = request.headers.get('Origin') || '';
    const allowedList = String(env.ALLOWED_ORIGIN || '*').split(',').map((x) => x.trim()).filter(Boolean);
    const allowAll = allowedList.includes('*');
    if (origin && !allowAll && !allowedList.includes(origin)) return new Response('Origin not allowed', { status: 403 });
    const corsOrigin = allowAll ? '*' : (allowedList.includes(origin) ? origin : allowedList[0]);
    const cors = {
      'Access-Control-Allow-Origin': corsOrigin,
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type, Accept',
      'Access-Control-Max-Age': '86400',
      'Vary': 'Origin',
    };
    const serverErr = (e) => { const m = String(e && e.message || e); return /daily|quota|exceed|storage limit/i.test(m) ? json({ error: 'writes_paused' }, 503) : json({ error: 'server_error', detail: m }, 500); };
    const json = (data, status = 200) => new Response(JSON.stringify(data), {
      status,
      headers: { ...cors, ...SEC_HEADERS, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
    });
    const url = new URL(request.url);
    // 25 Nov security pass: the assets binding serves the whole repo directory, so block
    // source/config/secret-shaped paths before anything else (worker runs first, see wrangler.toml).
    const pth = url.pathname.toLowerCase();
    if (pth.includes('/.') || /^\/(riders-map-worker|wa-gateway|relay|android|docs|desktop)(\/|$)/.test(pth)
        || /\.(toml|cjs|gs|md|sh|lock|zip|tar|gz|keystore|properties|json|yaml|yml|sql|env)$/.test(pth)) {
      return new Response('Not found', { status: 404 });
    }
    const SEC_HEADERS = {
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'camera=(), microphone=(), payment=()',
    };
    const CSP = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob: https:; connect-src 'self' https: wss:; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
    const withSec = (resp, isHtml) => {
      const h = new Headers(resp.headers);
      for (const [k, v] of Object.entries(SEC_HEADERS)) h.set(k, v);
      if (isHtml) h.set('Content-Security-Policy', CSP);
      return new Response(resp.body, { status: resp.status, headers: h });
    };
    const hub = env.RIDER_MAP_HUB.get(env.RIDER_MAP_HUB.idFromName('riders-global'));

    // 25 Nov: desktop download hosted here (replaces public GitHub release links before repo goes private).
    // The 126MB zip is chunked in /dl-chunks/ (assets limit 25MiB/file). Worker-side streaming hit the
    // free CPU cap mid-stream, so this page merges the chunks in the browser (plain cached 20MB GETs).
    if (url.pathname === '/dl/desktop' && request.method === 'GET') {
      const page = '<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TEAM MH | تحميل نسخة الكمبيوتر</title>'
        + '<style>body{margin:0;background:#101827;color:#edf2fa;font:17px system-ui;display:grid;place-items:center;min-height:100vh}main{max-width:430px;padding:24px;text-align:center}button{background:#2dc19f;color:#06231b;border:0;border-radius:10px;padding:14px 28px;font:inherit;font-weight:700;cursor:pointer}#bar{height:12px;border-radius:99px;background:#1b293e;overflow:hidden;margin:16px 0 6px}#fill{height:100%;width:0%;background:#2dc19f;transition:width .3s}.sub{color:#8fa1b8;font-size:14px}</style>'
        + '<main><h1>تحميل نسخة الكمبيوتر TEAM MH</h1><p class="sub">اضغط الزر واستنى شوية — الملف 126 ميجا، بيتجمّع وبيتحمّل لوحده.</p><button id="go">⬇️ تحميل team-mh-desktop-win-x64.zip</button><div id="bar" hidden><div id="fill"></div></div><p class="sub" id="st"></p></main>'
        + '<script>const chunks=["desktop-00.bin","desktop-01.bin","desktop-02.bin","desktop-03.bin","desktop-04.bin","desktop-05.bin","desktop-06.bin"];'
        + 'document.getElementById("go").onclick=async()=>{const st=document.getElementById("st"),fill=document.getElementById("fill");document.getElementById("bar").hidden=false;'
        + 'try{const parts=[];let done=0;for(const c of chunks){st.textContent="بيجمع جزء "+(done+1)+" من "+chunks.length+"...";const r=await fetch("/dl-chunks/"+c,{cache:"default"});if(!r.ok)throw new Error("fetch failed: "+r.status);parts.push(await r.arrayBuffer());done++;fill.style.width=(done/chunks.length*100)+"%"}'
        + 'st.textContent="بيحفظ الملف...";const blob=new Blob(parts,{type:"application/zip"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="team-mh-desktop-win-x64.zip";a.click();'
        + 'st.textContent="✅ اتحمّل — هتلاقيه في التنزيلات ("+(blob.size/1048576).toFixed(0)+" ميجا)"}catch(e){st.textContent="❌ حصلت مشكلة في التحميل — جرب تاني"} };</script>';
      const h = new Headers({ ...SEC_HEADERS, 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      h.set('Content-Security-Policy', "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'");
      return new Response(page, { headers: h });
    }

    // convenience: the current APK already lives at /app.apk
    if (url.pathname === '/dl/apk' && request.method === 'GET') {
      return Response.redirect(new URL('/app.apk', url).toString(), 302);
    }

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

    if (url.pathname.startsWith('/api/auth/')) {
      try {
        await ensureSchema(env);
        const handled = await handleAuth(request, env, json, url);
        if (handled) return handled;
      } catch (e) {
        return serverErr(e);
      }
      return json({ error: 'not_found' }, 404);
    }

    if (url.pathname.startsWith('/api/chat/')) {
      try {
        await ensureSchema(env);
        const handled = await handleChat(request, env, json, url);
        if (handled) return handled;
      } catch (e) {
        return serverErr(e);
      }
      return json({ error: 'not_found' }, 404);
    }

    if (url.pathname === '/api/agent/poll' && request.method === 'GET') {
      try {
        await ensureSchema(env);
        return await handleAgentPoll(request, env, json, url);
      } catch (e) {
        return serverErr(e);
      }
    }

    if (url.pathname.startsWith('/api/shiftcmd/')) {
      try {
        await ensureSchema(env);
        const handled = await handleShiftCmd(request, env, json, url);
        if (handled) return handled;
      } catch (e) {
        return serverErr(e);
      }
      return json({ error: 'not_found' }, 404);
    }

    if (url.pathname.startsWith('/api/hiring/')) {
      try {
        await ensureSchema(env);
        const handled = await handleHiring(request, env, json, url);
        if (handled) return handled;
      } catch (e) {
        return serverErr(e);
      }
      return json({ error: 'not_found' }, 404);
    }

    if (url.pathname === '/api/ui/tabs') {
      try {
        await ensureSchema(env);
        const user = await getSessionUser(env, request);
        if (!user) return json({ error: 'unauthorized' }, 401);
        if (request.method === 'GET') return json({ hidden: await getHiddenTabs(env), order: await getTabOrder(env) });
        if (request.method === 'POST') {
          if (user.r !== 'admin') return json({ error: 'forbidden' }, 403);
          const body = await request.json().catch(() => null) || {};
          if (Array.isArray(body.hidden)) {
            const list = body.hidden.map(x => String(x).slice(0, 40)).slice(0, 60);
            await env.DB.prepare("INSERT INTO settings(k,v) VALUES('hidden_tabs',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(JSON.stringify(list)).run();
          }
          if (Array.isArray(body.order)) {
            const list = body.order.map(x => String(x).slice(0, 40)).slice(0, 60);
            await env.DB.prepare("INSERT INTO settings(k,v) VALUES('tab_order',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(JSON.stringify(list)).run();
          }
          return json({ ok: true, hidden: await getHiddenTabs(env), order: await getTabOrder(env) });
        }
        return json({ error: 'method_not_allowed' }, 405);
      } catch (e) {
        return serverErr(e);
      }
    }

    if (url.pathname === '/api/notifications/test-seed' && request.method === 'POST') {
      if (!env.SEED_TOKEN || !safeEqual(request.headers.get('Authorization') || '', 'Bearer ' + env.SEED_TOKEN)) return json({ error: 'unauthorized' }, 401);
      await ensureSchema(env);
      const opts = await request.json().catch(() => null);
      const title = String(opts && opts.title || '⚠️ مندوب سمع تأخير').slice(0, 120);
      const rider = String(opts && opts.rider || 'أحمد سامي').slice(0, 80);
      const code = String(opts && opts.code || '2171071').replace(/[^0-9]/g, '').slice(0, 12);
      const zone = String(opts && opts.zone || '').trim().slice(0, 60);
      const mins = Math.min(999, Math.max(1, parseInt(opts && opts.minutes, 10) || 25));
      const bodyText = String(opts && opts.body || ('المندوب ' + rider + ' (كود ' + code + ')' + (zone ? ' - ' + zone : '') + ' سجّل تأخير ' + mins + ' دقيقة عن ميعاد الشيفت')).slice(0, 500);
      let targets = [];
      let matched = [];
      if (opts && opts.to) {
        const who = String(opts.to).trim().slice(0, 80);
        const zoneF = String(opts && opts.zoneFilter || '').trim().slice(0, 60);
        let rows = await env.DB.prepare("SELECT u,n,s FROM users WHERE status='active' AND (n=? OR u=?)").bind(who, who.toLowerCase()).all();
        if (!(rows.results || []).length) rows = await env.DB.prepare("SELECT u,n,s FROM users WHERE status='active' AND n LIKE ?").bind('%' + who.replace(/%/g, '') + '%').all();
        let list = rows.results || [];
        if (zoneF && list.length > 1) { const z = list.filter(r => String(r.s || '').includes(zoneF)); if (z.length) list = z; }
        targets = [...new Set(list.map(r => r.u))];
        matched = list.map(r => r.n);
        if (!targets.length) return json({ error: 'user_not_found' }, 404);
      } else {
        const rows = await env.DB.prepare("SELECT u FROM users WHERE status='active' AND r='admin'").all();
        targets = (rows.results || []).map(r => r.u);
      }
      for (const t of targets) await insertNotification(env, t, title, bodyText, code);
      return json({ ok: true, sent: targets.length, matched });
    }

    if (url.pathname === '/api/notifications/send' && request.method === 'POST') {
      try {
        await ensureSchema(env);
        const user = await getSessionUser(env, request);
        if (!user) return json({ error: 'unauthorized' }, 401);
        if (user.r !== 'admin' && user.r !== 'manager') return json({ error: 'forbidden' }, 403);
        const body = await request.json().catch(() => null);
        const title = String(body && body.title || '').trim().slice(0, 120);
        const text = String(body && body.body || '').trim().slice(0, 500);
        const target = String(body && body.target || 'all').trim().toLowerCase().slice(0, 60);
        if (!title && !text) return json({ error: 'missing_fields' }, 400);
        let targets = [];
        if (body && Array.isArray(body.targets) && body.targets.length) {
          const uniq = [...new Set(body.targets.map(t => String(t).toLowerCase().replace(/[^a-z0-9._-]/g, '').slice(0, 60)).filter(Boolean))].slice(0, 300);
          if (!uniq.length) return json({ error: 'missing_fields' }, 400);
          const rows = await env.DB.prepare(`SELECT u FROM users WHERE status='active' AND u IN (${uniq.map(() => '?').join(',')})`).bind(...uniq).all();
          targets = (rows.results || []).map(r => r.u);
          if (!targets.length) return json({ error: 'user_not_found' }, 404);
        } else if (target === 'all') {
          const rows = await env.DB.prepare("SELECT u FROM users WHERE status='active' AND r IN ('sup','manager')").all();
          targets = (rows.results || []).map(r => r.u);
        } else {
          const t = await env.DB.prepare("SELECT u FROM users WHERE u=? AND status='active'").bind(target).first();
          if (!t) return json({ error: 'user_not_found' }, 404);
          targets = [t.u];
        }
        const head = '📢 ' + (title || 'إشعار من الإدارة');
        const full = (text ? text : '') + ' — ' + (user.n || user.u);
        for (const u2 of targets) await insertNotification(env, u2, head, full, '');
        return json({ ok: true, sent: targets.length });
      } catch (e) {
        return serverErr(e);
      }
    }

    if (url.pathname === '/api/geo') {
      try {
        await ensureSchema(env);
        const user = await getSessionUser(env, request);
        if (!user) return json({ error: 'unauthorized' }, 401);
        if (request.method === 'POST') {
          const body = await request.json().catch(() => null);
          const lat = body && Number(body.lat), lon = body && Number(body.lon), acc = body && Number(body.acc);
          if (!Number.isFinite(lat) || !Number.isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) return json({ error: 'invalid_geo' }, 400);
          await env.DB.prepare('INSERT INTO geo(u,lat,lon,acc,ts) VALUES(?,?,?,?,?) ON CONFLICT(u) DO UPDATE SET lat=excluded.lat, lon=excluded.lon, acc=excluded.acc, ts=excluded.ts')
            .bind(user.u, lat, lon, Number.isFinite(acc) ? acc : null, Date.now()).run();
          return json({ ok: true });
        }
        if (request.method === 'GET') {
          if (user.r !== 'admin' && user.r !== 'manager') return json({ error: 'forbidden' }, 403);
          const rows = await env.DB.prepare('SELECT g.u, u.n, g.lat, g.lon, g.acc, g.ts FROM geo g JOIN users u ON u.u=g.u ORDER BY g.ts DESC').all();
          return json({ items: rows.results || [] });
        }
        return json({ error: 'not_found' }, 404);
      } catch (e) {
        return serverErr(e);
      }
    }

    if (url.pathname === '/api/theme') {
      await ensureSchema(env);
      if (request.method === 'GET') {
        const rows = await env.DB.prepare("SELECT k,v FROM settings WHERE k IN ('login_theme','login_title','login_sub')").all();
        const map = {};
        for (const r of (rows.results || [])) map[r.k] = r.v;
        return json({ theme: map.login_theme || 'night', title: map.login_title || '', sub: map.login_sub || '' });
      }
      if (request.method === 'POST') {
        const user = await getSessionUser(env, request);
        if (!user || user.r !== 'admin') return json({ error: 'unauthorized' }, 401);
        const body = await request.json().catch(() => null);
        const theme = String(body && body.theme || '').toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 24);
        if (!theme) return json({ error: 'missing_fields' }, 400);
        const stmts = [env.DB.prepare("INSERT INTO settings(k,v) VALUES('login_theme',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(theme)];
        if (body && typeof body.title === 'string') stmts.push(env.DB.prepare("INSERT INTO settings(k,v) VALUES('login_title',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(String(body.title).slice(0, 60)));
        if (body && typeof body.sub === 'string') stmts.push(env.DB.prepare("INSERT INTO settings(k,v) VALUES('login_sub',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(String(body.sub).slice(0, 120)));
        await env.DB.batch(stmts);
        return json({ ok: true, theme });
      }
    }

    if (url.pathname === '/api/push/register' && request.method === 'POST') {
      try {
        await ensureSchema(env);
        const user = await getSessionUser(env, request);
        if (!user) return json({ error: 'unauthorized' }, 401);
        const body = await request.json().catch(() => null);
        const token = String(body && body.token || '').trim().slice(0, 300);
        if (!token) return json({ error: 'missing_fields' }, 400);
        await env.DB.prepare('INSERT INTO push_tokens(u,token,ts) VALUES(?,?,?) ON CONFLICT(u,token) DO UPDATE SET ts=excluded.ts').bind(user.u, token, Date.now()).run();
        return json({ ok: true });
      } catch (e) { return serverErr(e); }
    }

    if (url.pathname === '/api/assistant' && request.method === 'POST') {
      try {
        const user = await getSessionUser(env, request);
        if (!user) return json({ error: 'unauthorized' }, 401);
        if (user.r !== 'admin' && user.r !== 'manager') return json({ error: 'forbidden' }, 403);
        if (!env.AI) return json({ error: 'ai_unavailable' }, 503);
        const dayKey = cairoDay() + ':' + user.u;
        const used = (_aiUse.get(dayKey) || 0);
        if (used >= 60) return json({ error: 'daily_limit' }, 429);
        _aiUse.set(dayKey, used + 1);
        if (_aiUse.size > 500) { for (const k of _aiUse.keys()) if (!k.startsWith(cairoDay())) _aiUse.delete(k); }
        const body = await request.json().catch(() => null);
        const q = String(body && body.q || '').trim().slice(0, 600);
        if (!q) return json({ error: 'missing_fields' }, 400);
        let ctxStr = '{}';
        try { ctxStr = JSON.stringify((body && body.ctx) || {}).slice(0, 9000); } catch (e) {}
        const sys = 'إنت "TEAM MH"، المساعد الذكي بتاع لوحة تحكم Team MH لمتابعة أداء المناديب (الطيارين). بتجاوب دايمًا بالعامية المصرية، باختصار ووضوح، وبتعتمد على البيانات اللي بتتبعتلك في رسالة المستخدم بس. متخترعش أرقام مش موجودة، ولو البيانات مش كفاية قول ده بصراحة. لو السؤال مش له علاقة بشغل اللوحة والمناديب والأرقام، اعتذر بأدب وقول إنك مساعد لوحة التحكم بس. نسّق الإجابة في سطور قصيرة، ولو فيها قائمة خلي كل بند في سطر.';
        const r = await env.AI.run('@cf/meta/llama-3.3-70b-instruct-fp8-fast', {
          messages: [
            { role: 'system', content: sys },
            { role: 'user', content: 'بيانات اللوحة الحالية (JSON):\n' + ctxStr + '\n\nالسؤال: ' + q },
          ],
          max_tokens: 600,
        });
        const ans = String((r && r.response) || '').trim();
        return json({ ok: true, answer: ans || 'معنديش إجابة واضحة من البيانات الحالية.' });
      } catch (e) { return serverErr(e); }
    }

    if (url.pathname === '/api/notifications' || url.pathname === '/api/notifications/test') {
      try {
        await ensureSchema(env);
        const user = await getSessionUser(env, request);
        if (!user) return json({ error: 'unauthorized' }, 401);
        if (url.pathname === '/api/notifications' && request.method === 'GET') {
          const day = cairoDay();
          const rows = await env.DB.prepare('SELECT id,title,body,rider_id,ts FROM notifications WHERE u=? AND day=? ORDER BY id DESC LIMIT 100').bind(user.u, day).all();
          const rd = await env.DB.prepare('SELECT ts FROM notifications_read WHERE u=?').bind(user.u).first();
          const readTs = (rd && rd.ts) || 0;
          const items = rows.results || [];
          return json({ day, count: items.length, unread: items.filter(i => i.ts > readTs).length, items });
        }
        if (url.pathname === '/api/notifications/read' && request.method === 'POST') {
          await env.DB.prepare('INSERT INTO notifications_read(u,ts) VALUES(?,?) ON CONFLICT(u) DO UPDATE SET ts=excluded.ts').bind(user.u, Date.now()).run();
          return json({ ok: true });
        }
        if (url.pathname === '/api/notifications/test' && request.method === 'POST') {
          if (user.r !== 'admin' && user.r !== 'manager') return json({ error: 'forbidden' }, 403);
          await insertNotification(env, user.u, 'تجربة', 'إشعار تجريبي من لوحة التحكم', '');
          return json({ ok: true });
        }
        return json({ error: 'not_found' }, 404);
      } catch (e) {
        return serverErr(e);
      }
    }

    if (url.pathname === '/health' && request.method === 'GET') return json({ ok: true });

    if (url.pathname === '/api/publish' && request.method === 'POST') {
      if (!env.APP_INGEST_TOKEN || !safeEqual(request.headers.get('Authorization') || '', `Bearer ${env.APP_INGEST_TOKEN}`)) return json({ error: 'unauthorized' }, 401);
      let payload;
      try {
        if (Number(request.headers.get('Content-Length') || 0) > MAX_BODY_BYTES) return json({ error: 'payload_too_large' }, 413);
        const raw = await request.text();
        if (new TextEncoder().encode(raw).length > MAX_BODY_BYTES) return json({ error: 'payload_too_large' }, 413);
        payload = JSON.parse(raw);
      } catch {
        return json({ error: 'invalid_json' }, 400);
      }
      if (!payload || !Array.isArray(payload.riders) || payload.riders.length > 5000) return json({ error: 'invalid_riders' }, 400);
      const riders = payload.riders.map((row) => {
        const latitude = Number(row?.latitude), longitude = Number(row?.longitude);
        if (!Number.isFinite(latitude) || !Number.isFinite(longitude) || Math.abs(latitude) > 90 || Math.abs(longitude) > 180 || (latitude === 0 && longitude === 0)) return null;
        const activeOrders = Array.isArray(row.active_orders) ? row.active_orders.slice(0, 20).map((order) => ({
          id: clean(order?.id, 60), status: clean(order?.status, 40),
          restaurant: clean(order?.restaurant, 100), waiting_since: clean(order?.waiting_since, 40),
          wait_minutes: finiteNumber(order?.wait_minutes, 0, 100000),
        })) : [];
        const activeDeliveryIds = Array.isArray(row.active_delivery_ids)
          ? row.active_delivery_ids.slice(0, 20).map((id) => clean(id, 60)) : [];
        return {
          id: clean(row.id, 60), name: clean(row.name, 120), supervisor: clean(row.supervisor, 120), city: clean(row.city, 80),
          zone: clean(row.zone, 100), state: clean(row.state, 40), latitude, longitude,
          updated_at: clean(row.updated_at, 40),
          deliveries: clean(row.deliveries, 30), time_worked: clean(row.time_worked, 40),
          late_time: clean(row.late_time, 40), breaks: clean(row.breaks, 20),
          breaks_time: clean(row.breaks_time, 40), acceptance_rate: clean(row.acceptance_rate, 30),
          utilization_rate: clean(row.utilization_rate, 30), wallet_balance: clean(row.wallet_balance, 30),
          ongoing_orders: finiteNumber(row.ongoing_orders, 0, 100000) ?? Math.max(activeOrders.length, activeDeliveryIds.length),
          active_delivery_ids: activeDeliveryIds, active_orders: activeOrders,
        };
      }).filter(Boolean);
      const snapshot = { updated_at: clean(payload.updated_at, 40) || new Date().toISOString(), riders };
      const stored = await hub.fetch('https://rider-map.internal/publish', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(snapshot),
      });
      if (!stored.ok) return json({ error: 'could_not_store_snapshot' }, 503);
      return json({ ok: true, riders: riders.length, updated_at: snapshot.updated_at });
    }

    if (url.pathname === '/api/riders' && request.method === 'GET') {
      const okMapToken = env.MAP_VIEW_TOKEN && safeEqual(request.headers.get('Authorization') || '', `Bearer ${env.MAP_VIEW_TOKEN}`);
      if (!okMapToken && !await getSessionUser(env, request)) return json({ error: 'unauthorized' }, 401);
      const response = await hub.fetch('https://rider-map.internal/snapshot');
      return json(await response.json());
    }

    if (url.pathname === '/api/forms/log' && request.method === 'GET') {
      const user = await getSessionUser(env, request);
      if (!user) return json({error:'unauthorized'},401);
      if (!['admin','manager','sup'].includes(user.r)) return json({error:'forbidden'},403);
      const action = url.searchParams.get('action');
      if (!['extend','break','open'].includes(action)) return json({error:'bad_action'},400);
      await ensureSchema(env);
      const since=Date.now()-48*3600000;
      const query=user.r==='admin'
        ?env.DB.prepare('SELECT id,u,action,rider_id,city,payload,result,ts FROM form_submissions WHERE action=? AND ts>=? ORDER BY ts DESC LIMIT 1000').bind(action,since)
        :env.DB.prepare('SELECT id,u,action,rider_id,city,payload,result,ts FROM form_submissions WHERE action=? AND ts>=? AND u=? ORDER BY ts DESC LIMIT 1000').bind(action,since,user.u);
      const data=await query.all();
      const today=cairoDay();
      return json({day:today,scope:user.r==='admin'?'all':'own',rows:(data.results||[]).filter(r=>cairoDay(r.ts)===today).map(r=>{let p={},v={};try{p=JSON.parse(r.payload)}catch{}try{v=JSON.parse(r.result)}catch{}const outcome=v.manual===true?'manual':v.ok===true?'confirmed':(String(v.error||'')==='submission_unconfirmed'?'unconfirmed':(String(v.error||'')==='nav_failed'&&v.detail==='did_not_advance')?'held':(String(v.error||'')==='auth_expired'?'auth':'failed'));return {id:r.id,u:r.u,rider_id:r.rider_id,city:r.city,ts:r.ts,duration:p.duration||p['entry.1552166535']||((p['entry.536642639_hour']||'')+':'+(p['entry.536642639_minute']||'')),reason:p.reason||p['entry.1831411232']||'',confirmed:v.ok===true,outcome,status:v.status||null,error:String(v.error||'').slice(0,120),detail:String(v.detail||'').slice(0,900),diag:v.diag||null}})});
    }

    if (url.pathname === '/api/forms/prefill' && request.method === 'POST') {
      const user = await getSessionUser(env, request);
      if (!user) return json({ error: 'unauthorized' }, 401);
      if (FORM_ACTIONS_ADMIN_ONLY ? user.r !== 'admin' : !['admin', 'manager', 'sup'].includes(user.r)) return json({ error: 'forbidden' }, 403);
      const body = await request.json().catch(() => ({}));
      const job = buildFormJob(body);
      if (job.error) return json({ error: job.error }, 400);
      return json({ ok: true, url: buildPrefillUrl(job.formId, job.fields) });
    }

    // team_mh desktop v0.3.0: best-effort log line for runs executed locally on the
    // laptop (real-Chrome walk). Never blocks the desktop; just records the outcome.
    if (url.pathname === '/api/forms/log-direct' && request.method === 'POST') {
      const user = await getSessionUser(env, request);
      if (!user) return json({ error: 'unauthorized' }, 401);
      if (!['admin', 'manager', 'sup'].includes(user.r)) return json({ error: 'forbidden' }, 403);
      const body = await request.json().catch(() => ({}));
      const action = String(body.action || '');
      if (!['extend', 'break', 'open'].includes(action)) return json({ error: 'bad_action' }, 400);
      const riderId = String(body.rider_id || '').replace(/[^0-9]/g, '');
      if (!riderId) return json({ error: 'bad_rider' }, 400);
      const city = String(body.city || '').trim();
      await ensureSchema(env);
      try {
        await env.DB.prepare('INSERT INTO form_submissions(u,action,rider_id,city,payload,result,ts) VALUES(?,?,?,?,?,?,?)')
          .bind(user.u, action, riderId, city,
            JSON.stringify({ duration: String(body.duration || ''), reason: String(body.reason || ''), engine: 'desktop-local' }),
            JSON.stringify(body.result && typeof body.result === 'object' ? body.result : {}),
            Date.now()).run();
      } catch (e) { return json({ ok: false, error: 'log_failed' }, 500); }
      return json({ ok: true });
    }

    if (url.pathname === '/api/forms/log-manual' && request.method === 'POST') {
      const user = await getSessionUser(env, request);
      if (!user) return json({ error: 'unauthorized' }, 401);
      if (FORM_ACTIONS_ADMIN_ONLY ? user.r !== 'admin' : !['admin', 'manager', 'sup'].includes(user.r)) return json({ error: 'forbidden' }, 403);
      const body = await request.json().catch(() => ({}));
      const job = buildFormJob(body);
      if (job.error) return json({ error: job.error }, 400);
      try {
        await ensureSchema(env);
        await env.DB.prepare('INSERT INTO form_submissions(u,action,rider_id,city,payload,result,ts) VALUES(?,?,?,?,?,?,?)').bind(user.u, job.action, job.riderId, job.city, JSON.stringify({ ...job.fields, duration: job.duration, reason: job.reason }), JSON.stringify({ manual: true }), Date.now()).run();
      } catch (e) { return json({ error: 'log_failed' }, 500); }
      return json({ ok: true });
    }

    if (url.pathname === '/api/forms/cookie' && request.method === 'POST') {
      const user = await getSessionUser(env, request);
      if (!user) return json({ error: 'unauthorized' }, 401);
      if (user.r !== 'admin') return json({ error: 'forbidden' }, 403);
      const body = await request.json().catch(() => ({}));
      const which = String(body.which || '');
      if (which !== 'alex' && which !== 'general') return json({ error: 'bad_form' }, 400);
      const cookie = String(body.cookie || '');
      if (cookie.length < 100 || cookie.length > 8000 || /[\r\n]/.test(cookie)) return json({ error: 'bad_cookie' }, 400);
      await ensureSchema(env);
      await env.DB.prepare('INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v').bind('form_cookie_' + which, cookie).run();
      return json({ ok: true, set: 'form_cookie_' + which });
    }

    if (url.pathname === '/api/forms/relay-cookie' && request.method === 'POST') {
      const user = await getSessionUser(env, request);
      if (!user) return json({ error: 'unauthorized' }, 401);
      if (user.r !== 'admin') return json({ error: 'forbidden' }, 403);
      const body = await request.json().catch(() => ({}));
      const which = String(body.which || '');
      if (which !== 'alex' && which !== 'general') return json({ error: 'bad_form' }, 400);
      const cookie = String(body.cookie || '');
      if (cookie.length < 100 || cookie.length > 8000 || /[\r\n]/.test(cookie)) return json({ error: 'bad_cookie' }, 400);
      const relayUrl = which === 'alex' ? env.FORM_RELAY_ALEX : env.FORM_RELAY_GENERAL;
      if (!relayUrl || !env.FORM_RELAY_SECRET) return json({ error: 'relay_not_configured' }, 503);
      const resp = await fetch(relayUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ secret: env.FORM_RELAY_SECRET, action: 'set_cookie', which, cookie }) });
      const result = await resp.json().catch(() => ({ error: 'invalid_relay_response' }));
      return json({ relay: true, result });
    }

    if (url.pathname === '/api/forms/probe-direct' && request.method === 'POST') {
      const user = await getSessionUser(env, request);
      if (!user) return json({ error: 'unauthorized' }, 401);
      if (user.r !== 'admin') return json({ error: 'forbidden' }, 403);
      const body = await request.json().catch(() => ({}));
      const which = String(body.form || '');
      const isAlex = which === 'alex';
      if (!isAlex && which !== 'general') return json({ error: 'bad_form' }, 400);
      await ensureSchema(env);
      const row = await env.DB.prepare('SELECT v FROM settings WHERE k=?').bind('form_cookie_' + which).first();
      if (!row || !row.v) return json({ error: 'no_cookie' }, 503);
      const fields = isAlex
        ? { 'entry.1976663790': '\u0634\u064a\u0641\u062a\u0627\u062a \u0627\u0644\u0637\u064a\u0627\u0631\u064a\u0646', 'entry.186608000': '1234567', 'entry.2117629487': '\u0627\u0644\u0628\u0631\u064a\u0643\u0627\u062a', 'entry.1290442973': '\u0641\u0643 \u0628\u0631\u064a\u0643', 'entry.1831411232': 'BREAK' }
        : { 'entry.302135773': '\u0634\u064a\u0641\u062a\u0627\u062a \u0627\u0644\u0637\u064a\u0627\u0631\u064a\u0646', 'entry.1941659317': '\u0641\u0643 \u0628\u0631\u064a\u0643', 'entry.264752225': '1234567', 'entry.1551386634': '\u0627\u0644\u063a\u0631\u0627\u062f\u0642\u0647' };
      const email = isAlex ? 'alexlogistics.teammh101@gmail.com' : 'deltalogistics.teammh1@gmail.com';
      try {
        const result = await walkFormDirect({ formId: GOOGLE_FORM_IDS[which], cookie: row.v, email, fields, probe: true });
        return json({ probe: true, direct: true, form: which, result });
      } catch (e) { return json({ probe: true, direct: true, form: which, result: { error: String(e && e.message || e).slice(0, 200), engine: 'direct' } }); }
    }

    if (url.pathname === '/api/forms/probe' && request.method === 'POST') {
      const user = await getSessionUser(env, request);
      if (!user) return json({ error: 'unauthorized' }, 401);
      if (FORM_ACTIONS_ADMIN_ONLY ? user.r !== 'admin' : !['admin', 'manager', 'sup'].includes(user.r)) return json({ error: 'forbidden' }, 403);
      const body = await request.json().catch(() => ({}));
      const which = String(body.form || '');
      const isAlex = which === 'alex';
      if (!isAlex && which !== 'general') return json({ error: 'bad_form' }, 400);
      const relayUrl = isAlex ? env.FORM_RELAY_ALEX : env.FORM_RELAY_GENERAL;
      if (!relayUrl || !env.FORM_RELAY_SECRET) return json({ error: 'relay_not_configured' }, 503);
      const fields = isAlex
        ? { 'entry.1976663790': 'شيفتات الطيارين', 'entry.186608000': '1234567', 'entry.2117629487': 'البريكات', 'entry.1290442973': 'فك بريك', 'entry.1831411232': 'BREAK' }
        : { 'entry.302135773': 'شيفتات الطيارين', 'entry.1941659317': 'فك بريك', 'entry.264752225': '1234567', 'entry.1551386634': 'الغرادقه' };
      const formId = isAlex ? '1FAIpQLSffSwyTh0w4AYjTU9AG-kj-0UfJHcSTSYnR1DrWJ_h8iPYm3Q' : '1FAIpQLSekxaUQPgiWq-Y_IPfsTx7wTANA324a2JklFJZ_Gxg9CGPaKA';
      const resp = await fetch(relayUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ secret: env.FORM_RELAY_SECRET, action: 'probe', formId, fields }) });
      const result = await resp.json().catch(() => ({ error: 'invalid_relay_response' }));
      return json({ probe: true, form: which, result });
    }


    // Phone-session form queue: the admin's APK polls for jobs and submits them
    // from the phone's own Google session (docs.google.com cookies in the app WebView).
    if (url.pathname === '/api/forms/phone-enqueue' && request.method === 'POST') {
      const user = await getSessionUser(env, request);
      if (!user) return json({ error: 'unauthorized' }, 401);
      if (!['admin', 'manager', 'sup'].includes(user.r)) return json({ error: 'forbidden' }, 403);
      if (FORM_ACTIONS_ADMIN_ONLY && user.r !== 'admin') return json({ error: 'forbidden' }, 403);
      const body = await request.json().catch(() => ({}));
      const job = buildFormJob(body);
      if (job.error) return json({ error: job.error }, 400);
      await ensureSchema(env);
      const now = Date.now();
      const dup = await env.DB.prepare("SELECT id FROM form_phone_jobs WHERE status IN ('pending','claimed') AND json_extract(job,'$.riderId')=? AND json_extract(job,'$.action')=? AND json_extract(job,'$.city')=? LIMIT 1").bind(job.riderId, job.action, job.city).all();
      if ((dup.results || []).length) return json({ error: 'already_queued', job_id: dup.results[0].id }, 409);
      const ins = await env.DB.prepare('INSERT INTO form_phone_jobs(u,job,status,ts,updated) VALUES(?,?,?,?,?)').bind(user.u, JSON.stringify(job), 'pending', now, now).run();
      return json({ ok: true, id: ins.meta.last_row_id });
    }

    if (url.pathname === '/api/forms/phone-poll' && request.method === 'GET') {
      const user = await getSessionUser(env, request);
      if (!user) return json({ error: 'unauthorized' }, 401);
      if (user.r !== 'admin') return json({ error: 'forbidden' }, 403);
      await ensureSchema(env);
      const now = Date.now();
      try { await env.DB.prepare("INSERT INTO settings(k,v) VALUES('phone_agent_seen',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(String(now)).run(); } catch {}
      await env.DB.prepare("UPDATE form_phone_jobs SET status='pending',updated=? WHERE status='claimed' AND updated<?").bind(now, now - 3 * 60 * 1000).run();
      const lastRow = await env.DB.prepare("SELECT v FROM settings WHERE k='phone_agent_lastjob'").first();
      const lastJob = lastRow ? Number(lastRow.v) : 0;
      if (lastJob && now - lastJob < 90 * 1000) return json({ ok: true, job: null, pace_wait: Math.ceil((90 * 1000 - (now - lastJob)) / 1000) });
      const row = await env.DB.prepare("SELECT id,job FROM form_phone_jobs WHERE status='pending' ORDER BY id LIMIT 1").first();
      if (!row) return json({ ok: true, job: null });
      await env.DB.prepare("UPDATE form_phone_jobs SET status='claimed',updated=? WHERE id=? AND status='pending'").bind(now, row.id).run();
      let job = {}; try { job = JSON.parse(row.job); } catch {}
      job.id = row.id;
      job.url = 'https://docs.google.com/forms/u/0/d/e/' + job.formId + '/viewform';
      job.email = job.isAlex ? 'alexlogistics.teammh101@gmail.com' : 'deltalogistics.teammh1@gmail.com';
      return json({ ok: true, job });
    }

    if (url.pathname === '/api/forms/phone-report' && request.method === 'POST') {
      const user = await getSessionUser(env, request);
      if (!user) return json({ error: 'unauthorized' }, 401);
      if (user.r !== 'admin') return json({ error: 'forbidden' }, 403);
      const body = await request.json().catch(() => ({}));
      const id = Number(body.id || 0);
      if (!id) return json({ error: 'missing_id' }, 400);
      await ensureSchema(env);
      const row = await env.DB.prepare('SELECT id,u,job,status FROM form_phone_jobs WHERE id=?').bind(id).first();
      if (!row) return json({ error: 'unknown_job' }, 404);
      const now = Date.now();
      const result = { engine: 'phone', ok: !!body.ok, error: body.error || null, detail: body.detail || null, status: body.status || null, submitted: !!body.submitted };
      const retry = body.retry === true && body.error === 'auth_expired';
      await env.DB.prepare('UPDATE form_phone_jobs SET status=?,result=?,updated=? WHERE id=?').bind(retry ? 'pending' : (body.ok ? 'done' : 'error'), JSON.stringify(result), now, id).run();
      if (!retry) {
        try { await env.DB.prepare("INSERT INTO settings(k,v) VALUES('phone_agent_lastjob',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(String(now)).run(); } catch {}
        let job = {}; try { job = JSON.parse(row.job); } catch {}
        try { await env.DB.prepare('INSERT INTO form_submissions(u,action,rider_id,city,payload,result,ts) VALUES(?,?,?,?,?,?,?)').bind(row.u, job.action || '', job.riderId || '', job.city || '', JSON.stringify({ ...(job.fields || {}), duration: job.duration, reason: job.reason }), JSON.stringify(result), now).run(); } catch {}
      }
      return json({ ok: true });
    }

    if (url.pathname === '/api/forms/phone-jobs' && request.method === 'GET') {
      const user = await getSessionUser(env, request);
      if (!user) return json({ error: 'unauthorized' }, 401);
      if (user.r !== 'admin') return json({ error: 'forbidden' }, 403);
      await ensureSchema(env);
      const rows = await env.DB.prepare('SELECT id,u,job,status,result,ts,updated FROM form_phone_jobs ORDER BY id DESC LIMIT 20').all();
      const jobs = (rows.results || []).map(r => { let j = {}; let res = {}; try { j = JSON.parse(r.job); } catch {} try { res = JSON.parse(r.result || '{}'); } catch {} return { id: r.id, by: r.u, action: j.action, rider_id: j.riderId, city: j.city, status: r.status, result: res, ts: r.ts, updated: r.updated }; });
      return json({ ok: true, jobs });
    }

    if (url.pathname === '/api/forms/phone-agent' && request.method === 'GET') {
      const user = await getSessionUser(env, request);
      if (!user) return json({ error: 'unauthorized' }, 401);
      if (!['admin', 'manager'].includes(user.r)) return json({ error: 'forbidden' }, 403);
      await ensureSchema(env);
      const row = await env.DB.prepare("SELECT v FROM settings WHERE k='phone_agent_seen'").first();
      const seen = row ? Number(row.v) : 0;
      return json({ ok: true, seen, online: !!seen && (Date.now() - seen) < 60 * 1000 });
    }

    // APK signing keystore escrow (base64 JKS) - recoverable only by admin session.
    if (url.pathname === '/api/admin/apk-keystore' && request.method === 'POST') {
      const user = await getSessionUser(env, request);
      if (!user) return json({ error: 'unauthorized' }, 401);
      if (user.r !== 'admin') return json({ error: 'forbidden' }, 403);
      const body = await request.json().catch(() => ({}));
      const b64 = String(body.b64 || '');
      if (b64.length < 1000 || b64.length > 200000 || !/^[A-Za-z0-9+/=]+$/.test(b64)) return json({ error: 'bad_keystore' }, 400);
      await ensureSchema(env);
      await env.DB.prepare('INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v').bind('apk_keystore_v2', b64).run();
      return json({ ok: true, bytes: b64.length });
    }

    if (url.pathname === '/api/forms/submit' && request.method === 'POST') {
      const user = await getSessionUser(env, request);
      if (!user) return json({ error: 'unauthorized' }, 401);
      if (!['admin', 'manager', 'sup'].includes(user.r)) return json({ error: 'forbidden' }, 403);
      if (FORM_ACTIONS_ADMIN_ONLY && user.r !== 'admin') return json({ error: 'forbidden' }, 403);
      const body = await request.json().catch(() => ({}));
      const job = buildFormJob(body);
      if (job.error) return json({ error: job.error }, 400);
      const { action, riderId, city, duration, reason, isAlex, fields, pageHistory, formId } = job;
      const relayUrl = isAlex ? env.FORM_RELAY_ALEX : env.FORM_RELAY_GENERAL;
      if (!relayUrl || !env.FORM_RELAY_SECRET) return json({ error: 'relay_not_configured' }, 503);
      // Queue/spacing + uncertainty retry-guard (Google Forms cooldown protection)
      const nowTs = Date.now();
      try {
        await ensureSchema(env);
        const lastRow = await env.DB.prepare("SELECT MAX(ts) AS last FROM form_submissions WHERE (CASE WHEN city='الإسكندرية' THEN 1 ELSE 0 END)=?").bind(isAlex ? 1 : 0).first();
        const lastTs = lastRow && lastRow.last ? Number(lastRow.last) : 0;
        const MIN_GAP = 90 * 1000;
        if (lastTs && nowTs - lastTs < MIN_GAP) return json({ error: 'rate_limited', wait: Math.ceil((MIN_GAP - (nowTs - lastTs)) / 1000) }, 429);
        const dup = await env.DB.prepare('SELECT id,result FROM form_submissions WHERE action=? AND rider_id=? AND city=? AND ts>=? ORDER BY ts DESC LIMIT 1').bind(action, riderId, city, nowTs - 30 * 60 * 1000).all();
        const prev = (dup.results || [])[0];
        if (prev) {
          let v = {}; try { v = JSON.parse(prev.result) } catch {}
          if (v.ok === true) return json({ error: 'already_submitted', submission_id: prev.id }, 409);
          return json({ error: 'uncertain_check_sheet', submission_id: prev.id }, 409);
        }
      } catch (e) { /* logging/guard failure must not block a submission */ }
      const resp = await fetch(relayUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ secret: env.FORM_RELAY_SECRET, formId, fields, pageHistory }) });
      const result = await resp.json().catch(() => ({error:'invalid_relay_response'}));
      let logSaved=true;
      try { await ensureSchema(env);await env.DB.prepare('INSERT INTO form_submissions(u,action,rider_id,city,payload,result,ts) VALUES(?,?,?,?,?,?,?)').bind(user.u, action, riderId, city, JSON.stringify({...fields,duration,reason}), JSON.stringify(result), Date.now()).run(); } catch (e) {logSaved=false;}
      if (result.error === 'auth_expired') return json({ error: 'صلاحية الفورم انتهت. الإدارة هتجددها، جرب تاني بعد شوية.', code: 'relay_auth_expired' }, 502);
      if (!resp.ok || result.ok !== true || result.error || (result.status && result.status >= 400)) {
        const re = String(result.error || '');
        const code = re === 'submission_unconfirmed' ? 'unconfirmed_check_sheet'
          : (re === 'nav_failed' && result.detail === 'did_not_advance') ? 'gateway_hold'
          : re === 'auth_expired' ? 'relay_auth_expired' : 'relay_failed';
        return json({ error: code, detail: result.error || ('HTTP ' + (result.status || resp.status)) }, 502);
      }
      return json({ ok: true, result,log_saved:logSaved });
    }

    if (url.pathname === '/api/ws-ticket' && request.method === 'POST') {
      const okMapToken = env.MAP_VIEW_TOKEN && safeEqual(request.headers.get('Authorization') || '', `Bearer ${env.MAP_VIEW_TOKEN}`);
      if (!okMapToken && !await getSessionUser(env, request)) return json({ error: 'unauthorized' }, 401);
      const ticket = `${crypto.randomUUID()}${crypto.randomUUID()}`;
      const response = await hub.fetch('https://rider-map.internal/ticket', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ticket }),
      });
      if (!response.ok) return json({ error: 'could_not_create_ticket' }, 503);
      return json({ ticket });
    }

    if (url.pathname === '/ws' && request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
      if (!url.searchParams.get('ticket')) return new Response('Missing ticket', { status: 401 });
      const doRequest = new Request(`https://rider-map.internal/ws?ticket=${encodeURIComponent(url.searchParams.get('ticket'))}`, request);
      return hub.fetch(doRequest);
    }

    if (url.pathname === '/api/admin/usage' && request.method === 'GET') {
      try {
        await ensureSchema(env);
        const user = await getSessionUser(env, request);
        if (!user) return json({ error: 'unauthorized' }, 401);
        if (user.r !== 'admin') return json({ error: 'forbidden' }, 403);
        const reset = nextUtcMidnight();
        const day = utcDay();
        // Hiring storage footprint (Micheal 25 Nov): images are the heavy rows.
        let hiring = null;
        try {
          const img = await env.DB.prepare('SELECT COUNT(*) c, COALESCE(SUM(LENGTH(data)),0) b FROM hiring_images').first();
          const req = await env.DB.prepare('SELECT COUNT(*) c FROM hiring_requests').first();
          hiring = { requests: (req && req.c) || 0, images: (img && img.c) || 0, image_bytes: (img && img.b) || 0, d1_db_limit_bytes: 500 * 1024 * 1024 };
        } catch (e) {}
        if (env.CF_API_TOKEN && env.CF_ACCOUNT_ID) {
          try {
            const used = await usageFromCloudflare(env);
            return json({ ok: true, source: 'cloudflare', scope: 'account', limit: QUOTA_DAILY_LIMIT, used, remaining: Math.max(0, QUOTA_DAILY_LIMIT - used), day, hiring, reset_at: reset.toISOString() });
          } catch (e) {
            const used = await usageEstimate(env);
            return json({ ok: true, source: 'estimate', scope: 'worker', cloudflare_error: String(e && e.message || e).slice(0, 200), limit: QUOTA_DAILY_LIMIT, used, remaining: Math.max(0, QUOTA_DAILY_LIMIT - used), day, hiring, reset_at: reset.toISOString() });
          }
        }
        const used = await usageEstimate(env);
        return json({ ok: true, source: 'estimate', scope: 'worker', limit: QUOTA_DAILY_LIMIT, used, remaining: Math.max(0, QUOTA_DAILY_LIMIT - used), day, hiring, reset_at: reset.toISOString() });
      } catch (e) {
        return serverErr(e);
      }
    }

    // static assets: worker runs first (run_worker_first), so fetch from the assets binding
    if (request.method === 'GET' || request.method === 'HEAD') {
      const assetResp = await env.ASSETS.fetch(request);
      if (assetResp.status !== 404) {
        const ct = assetResp.headers.get('Content-Type') || '';
        return withSec(assetResp, /text\/html/.test(ct));
      }
    }
    return json({ error: 'not_found' }, 404);
  },

  async scheduled(event, env, ctx) {
    bumpUsage(env, ctx);
    ctx.waitUntil(runStatusCron(env).catch(() => {}));
  },
};

export class RiderMapHub extends DurableObject {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/publish' && request.method === 'POST') {
      const snapshot = await request.json();
      await this.ctx.storage.put('snapshot', snapshot);
      await this.ctx.storage.setAlarm(Date.now() + SNAPSHOT_TTL_MS);
      const message = JSON.stringify({ type: 'snapshot', snapshot });
      for (const socket of this.ctx.getWebSockets()) {
        try { socket.send(message); } catch { try { socket.close(1011, 'send failed'); } catch {} }
      }
      return Response.json({ ok: true });
    }
    if (url.pathname === '/snapshot' && request.method === 'GET') {
      const snapshot = await this.ctx.storage.get('snapshot');
      if (!snapshot || Date.now() - Date.parse(snapshot.updated_at) > SNAPSHOT_TTL_MS) return Response.json({ updated_at: null, riders: [] });
      return Response.json(snapshot);
    }
    if (url.pathname === '/ticket' && request.method === 'POST') {
      const { ticket } = await request.json();
      await this.ctx.storage.put(`ticket:${ticket}`, Date.now() + 30_000);
      return Response.json({ ok: true });
    }
    if (url.pathname === '/ws' && request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
      const ticket = url.searchParams.get('ticket') || '';
      const expires = await this.ctx.storage.get(`ticket:${ticket}`);
      await this.ctx.storage.delete(`ticket:${ticket}`);
      if (!expires || expires < Date.now()) return new Response('Invalid or expired ticket', { status: 401 });
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      this.ctx.acceptWebSocket(server);
      server.serializeAttachment({ connectedAt: Date.now() });
      const snapshot = await this.ctx.storage.get('snapshot');
      if (snapshot && Date.now() - Date.parse(snapshot.updated_at) <= SNAPSHOT_TTL_MS) {
        server.send(JSON.stringify({ type: 'snapshot', snapshot }));
      }
      return new Response(null, { status: 101, webSocket: client });
    }
    return new Response('Not found', { status: 404 });
  }

  async alarm() {
    const snapshot = await this.ctx.storage.get('snapshot');
    if (snapshot && Date.now() - Date.parse(snapshot.updated_at) >= SNAPSHOT_TTL_MS) await this.ctx.storage.delete('snapshot');
    for (const key of await this.ctx.storage.list({ prefix: 'ticket:' })) {
      if (key[1] < Date.now()) await this.ctx.storage.delete(key[0]);
    }
  }

  async webSocketMessage(socket, message) {
    if (message === 'ping') socket.send('pong');
  }
}

function clean(value, maxLength) {
  return String(value ?? '').replace(/[\u0000-\u001f\u007f]/g, '').slice(0, maxLength);
}

function finiteNumber(value, min, max) {
  if (value === null || value === undefined || value === '') return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= min && number <= max ? number : null;
}

function safeEqual(a, b) {
  a = String(a); b = String(b);
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let index = 0; index < a.length; index++) mismatch |= a.charCodeAt(index) ^ b.charCodeAt(index);
  return mismatch === 0;
}
