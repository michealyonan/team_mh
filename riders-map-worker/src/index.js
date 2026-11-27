import { DurableObject } from 'cloudflare:workers';
import { makeTursoDb } from './turso.js';

/* 27 Nov staging (Micheal 24282605): when TURSO_URL + TURSO_AUTH_TOKEN secrets exist,
   ALL database traffic goes to Turso instead of D1 (staging copy only; live has no such
   secrets, so nothing changes there). The Turso adapter mimics the D1 binding surface.
   STAGING=1 also disables FCM fanout so the staging cron never double-pushes supervisors. */
function dbOf(env) {
  if (env.TURSO_URL && env.TURSO_AUTH_TOKEN) {
    if (!env.__turso) Object.defineProperty(env, '__turso', { value: makeTursoDb(env.TURSO_URL, env.TURSO_AUTH_TOKEN), enumerable: false });
    return env.__turso;
  }
  return env.DB;
}
function withDb(env) {
  if (!(env.TURSO_URL && env.TURSO_AUTH_TOKEN)) return env;
  const e = Object.create(env);
  Object.defineProperty(e, 'DB', { get: () => dbOf(env) });
  return e;
}

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
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS legal_reminders(case_id INTEGER PRIMARY KEY, by_u TEXT NOT NULL, by_name TEXT NOT NULL DEFAULT '', ts INTEGER NOT NULL, seen INTEGER NOT NULL DEFAULT 0)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT NOT NULL DEFAULT '')`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS push_tokens(u TEXT NOT NULL, token TEXT NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY(u, token))`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS push_log(u TEXT NOT NULL, token_tail TEXT NOT NULL, status INTEGER NOT NULL, resp TEXT NOT NULL, ts INTEGER NOT NULL)`),
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
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS status_meta(k TEXT PRIMARY KEY, v TEXT NOT NULL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS assistant_history(u TEXT NOT NULL, ts INTEGER NOT NULL, q TEXT NOT NULL DEFAULT '', a TEXT NOT NULL DEFAULT '')`),
    env.DB.prepare(`CREATE INDEX IF NOT EXISTS ah_u_ts ON assistant_history(u, ts)`),
    env.DB.prepare(`CREATE INDEX IF NOT EXISTS form_submissions_user_ts ON form_submissions(u,ts)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS form_phone_jobs(id INTEGER PRIMARY KEY AUTOINCREMENT,u TEXT NOT NULL,job TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',result TEXT NOT NULL DEFAULT '',ts INTEGER NOT NULL,updated INTEGER NOT NULL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS hiring_requests(id INTEGER PRIMARY KEY AUTOINCREMENT,u TEXT NOT NULL,payload TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',result TEXT NOT NULL DEFAULT '',ts INTEGER NOT NULL,updated INTEGER NOT NULL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS hiring_images(request_id INTEGER NOT NULL,k TEXT NOT NULL,data TEXT NOT NULL,PRIMARY KEY(request_id,k))`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS legal_cases(id INTEGER PRIMARY KEY AUTOINCREMENT,rider_id TEXT NOT NULL,rider_name TEXT NOT NULL,national_id TEXT NOT NULL,amount TEXT NOT NULL,phone TEXT NOT NULL,phone2 TEXT NOT NULL DEFAULT '',city TEXT NOT NULL DEFAULT '',u TEXT NOT NULL,u_name TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'received',case_number TEXT NOT NULL DEFAULT '',settle_amount TEXT NOT NULL DEFAULT '',judgment_status TEXT NOT NULL DEFAULT '',judgment_detail TEXT NOT NULL DEFAULT '',judgment_amount TEXT NOT NULL DEFAULT '',created INTEGER NOT NULL,updated INTEGER NOT NULL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS legal_case_images(case_id INTEGER NOT NULL,k TEXT NOT NULL,data TEXT NOT NULL,PRIMARY KEY(case_id,k))`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS legal_case_history(id INTEGER PRIMARY KEY AUTOINCREMENT,case_id INTEGER NOT NULL,status TEXT NOT NULL,note TEXT NOT NULL DEFAULT '',by_u TEXT NOT NULL,by_name TEXT NOT NULL,ts INTEGER NOT NULL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS rider_stops(
      rider_id TEXT PRIMARY KEY,
      lat REAL NOT NULL DEFAULT 0,
      lng REAL NOT NULL DEFAULT 0,
      since INTEGER NOT NULL DEFAULT 0,
      alerted INTEGER NOT NULL DEFAULT 0,
      seen_at INTEGER NOT NULL DEFAULT 0)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS legal_case_deletes(id INTEGER PRIMARY KEY AUTOINCREMENT,case_id INTEGER NOT NULL,snapshot TEXT NOT NULL DEFAULT '',by_u TEXT NOT NULL,by_name TEXT NOT NULL,ts INTEGER NOT NULL)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS shift_commands(id INTEGER PRIMARY KEY AUTOINCREMENT,u TEXT NOT NULL,payload TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',result TEXT NOT NULL DEFAULT '',ts INTEGER NOT NULL,updated INTEGER NOT NULL)`),
    // Scheduled shift commands (Micheal 26 Nov: اعتماد الكل) — admin sets action/time/repeat,
    // the 2-min cron enqueues real shift_commands when due; the desktop executes them as usual.
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS shiftcmd_schedules(id INTEGER PRIMARY KEY AUTOINCREMENT,action TEXT NOT NULL,target TEXT NOT NULL DEFAULT 'codes',codes TEXT NOT NULL DEFAULT '',city TEXT NOT NULL DEFAULT '',duration24 TEXT NOT NULL DEFAULT '',reason TEXT NOT NULL DEFAULT '',vehicle TEXT NOT NULL DEFAULT '',time_hhmm TEXT NOT NULL,daily INTEGER NOT NULL DEFAULT 1,enabled INTEGER NOT NULL DEFAULT 1,by_u TEXT NOT NULL,by_name TEXT NOT NULL DEFAULT '',last_run TEXT NOT NULL DEFAULT '',created INTEGER NOT NULL)`),
    // تقارير المشرفين: سجل إرسالات التقارير بالإيميل (Micheal 25 Nov) — مين بعت وإمتى وكم واحد وصل
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS report_logs(id INTEGER PRIMARY KEY AUTOINCREMENT,admin_u TEXT NOT NULL,day TEXT NOT NULL,types TEXT NOT NULL,sent INTEGER NOT NULL,failed INTEGER NOT NULL,ts INTEGER NOT NULL)`),
  ]);
  try { await env.DB.prepare("ALTER TABLE users ADD COLUMN photo TEXT NOT NULL DEFAULT ''").run(); } catch {}
  // rider zone (26 Nov) - lets scheduled 'break_all' rules route each rider to his own form.
  try { await env.DB.prepare("ALTER TABLE rider_states ADD COLUMN zone TEXT NOT NULL DEFAULT ''").run(); } catch {}
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

/* Cron slot claim: first worker to write the slot owns it; the other skips. Fixed-width numeric
   prefix keeps the text comparison valid. Fail-open: if the lock write itself errors, run anyway. */
async function claimCronSlot(env, key, slot) {
  try {
    const v = String(slot).padStart(12, '0');
    const r = await env.DB.prepare("INSERT INTO status_meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v WHERE status_meta.v < excluded.v").bind(key, v).run();
    return !!(r && r.meta && r.meta.changes > 0);
  } catch (e) { return true; }
}

async function isMapPaused(env) {
  try { const r = await env.DB.prepare("SELECT v FROM status_meta WHERE k='map_paused'").first(); return !!(r && r.v === '1'); } catch (e) { return false; }
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
// Tabs in DEFAULT_HIDDEN start hidden for non-admins even with no stored setting
// (Micheal 16458387: أمر مد وفك بريك stays eye-off until the admin opens it).
const DEFAULT_HIDDEN_TABS = ['shiftcmd'];
async function getHiddenTabs(env) {
  try {
    const row = await env.DB.prepare("SELECT v FROM settings WHERE k='hidden_tabs'").first();
    const a = JSON.parse((row && row.v) || '[]');
    const list = Array.isArray(a) ? a.map(String) : [];
    const srow = await env.DB.prepare("SELECT v FROM settings WHERE k='shown_tabs'").first();
    const sh = JSON.parse((srow && srow.v) || '[]');
    const shown = new Set(Array.isArray(sh) ? sh.map(String) : []);
    for (const t of DEFAULT_HIDDEN_TABS) if (!shown.has(t) && !list.includes(t)) list.push(t);
    return list;
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

async function chatFeatures(env) {
  // Micheal 26 Nov (21177591): admin switches for chat photo/voice sending.
  // Default ON (missing settings rows) so behavior is unchanged until an admin turns one off.
  let photo = true, voice = true;
  try {
    const rows = await env.DB.prepare("SELECT k,v FROM settings WHERE k IN ('chat_photo','chat_voice')").all();
    for (const r of (rows.results || [])) {
      if (r.k === 'chat_photo') photo = r.v !== '0';
      if (r.k === 'chat_voice') voice = r.v !== '0';
    }
  } catch (e) {}
  return { photo, voice };
}
async function insertNotification(env, u, title, body, riderId, color) {
  const r = await env.DB.prepare('INSERT INTO notifications(u,day,title,body,rider_id,ts) VALUES(?,?,?,?,?,?)')
    .bind(u, cairoDay(), String(title || '').slice(0, 120), String(body || '').slice(0, 500), String(riderId || '').slice(0, 40), Date.now()).run();
  await sendFcmToUser(env, u, String(title || '').slice(0, 120), String(body || '').slice(0, 500), riderId, color);
  return (r && r.meta && r.meta.rows_written) || 0;
}
// Status-change styling (27 Nov): emoji marker + Android small-icon tint per new state.
// Micheal 24214827: dot by NEW state - LATE red, STARTING yellow, READY green, WORKING blue,
// BREAK brown. TEMP_NOT_WORKING/ENDING he didn't specify: black/orange.
const STATE_STYLE = {
  WORKING: ['🔵', '#2563eb'], BREAK: ['🟤', '#92400e'], LATE: ['🔴', '#dc2626'],
  TEMP_NOT_WORKING: ['⚫', '#111827'], ENDING: ['🟠', '#ea580c'], STARTING: ['🟡', '#eab308'],
  READY: ['🟢', '#16a34a'], _: ['🔔', '#475569'],
};

async function enforceDeviceLimit(env, u, maxSessions) {
  const rows = await env.DB.prepare('SELECT token FROM sessions WHERE u=? AND expires>? ORDER BY created DESC').bind(u, Date.now()).all();
  const list = (rows.results || []).map(r => r.token);
  const excess = list.slice(Math.max(0, (maxSessions || 4) - 1));
  for (const t of excess) await env.DB.prepare('DELETE FROM sessions WHERE token=?').bind(t).run();
}

async function issueSession(env, u, remember) {
  const token = randHex(32);
  const ttl = 24 * 60 * 60 * 1000; // Micheal 26 Nov: كل جلسة 24 ساعة، من غير خانة تذكرني
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
async function sendFcmToUser(env, u, title, body, riderId, color) {
  // 27 Nov (24301978): staging now pushes normally - during the Turso load test it is the
  // single notifier (the live cron stands down via /api/admin/notif_pause), so no double pushes.
  if (!env.FCM_SA_JSON) {
    try { await env.DB.prepare('INSERT INTO push_log(u,token_tail,status,resp,ts) VALUES(?,?,?,?,?)').bind(u, '', -4, 'fcm_not_configured', Date.now()).run(); } catch (e) {}
    return;
  }
  try {
    const rows = await env.DB.prepare('SELECT token FROM push_tokens WHERE u=?').bind(u).all();
    const tokens = (rows.results || []).map(r => r.token);
    if (!tokens.length) return; // 26 Nov quota cut: was logging a no_tokens row per notification per user
    const at = await fcmAccessToken(env);
    const proj = env.FCM_PROJECT_ID || 'pilot-dashboard-d0983';
    for (const t of tokens.slice(0, 20)) {
      const tail = String(t).slice(-8);
      try {
        const r = await fetch(`https://fcm.googleapis.com/v1/projects/${proj}/messages:send`, {
          method: 'POST', headers: { 'Authorization': 'Bearer ' + at, 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: {
            token: t,
            notification: { title: String(title || ''), body: String(body || '') },
            android: { priority: 'HIGH', notification: Object.assign({ sound: 'default', channel_id: 'teammh_alerts' }, color ? { color } : {}) },
            data: { rider_id: String(riderId || ''), title: String(title || ''), body: String(body || '') },
          } }),
        });
        let respTxt = '';
        try { respTxt = await r.text(); } catch (e) { respTxt = 'read_error'; }
        // 26 Nov quota cut: log only failed pushes (success logging wrote 1 row per token per notification -
        // the state-flip flood burned tens of thousands of D1 writes on push_log alone).
        if (r.status !== 200) { try { await env.DB.prepare('INSERT INTO push_log(u,token_tail,status,resp,ts) VALUES(?,?,?,?,?)').bind(u, tail, r.status, respTxt.slice(0, 500), Date.now()).run(); } catch (e) {} }
        if (r.status === 404) await env.DB.prepare('DELETE FROM push_tokens WHERE token=?').bind(t).run();
      } catch (e) {
        try { await env.DB.prepare('INSERT INTO push_log(u,token_tail,status,resp,ts) VALUES(?,?,?,?,?)').bind(u, tail, -2, String(e).slice(0, 300), Date.now()).run(); } catch (e2) {}
      }
    }
  } catch (e) { await log(-3, String(e)); }
}

async function sendMail(env, to, subject, text, attachment) {
  if (!env.BREVO_API_KEY) return { ok: false, error: 'mail_not_configured' };
  try {
    const payload = {
      sender: { email: env.MAIL_FROM || 'michealuonanayad@gmail.com', name: 'لوحة أداء الطيارين' },
      to: [{ email: to }], subject, textContent: text,
    };
    // attachment: { name, content } where content is base64 (Brevo inline-attachment API)
    if (attachment && attachment.content) payload.attachment = [{ content: attachment.content, name: attachment.name || 'attachment.xlsx' }];
    const r = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: { 'api-key': env.BREVO_API_KEY, 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify(payload),
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

// 26 Nov speed pass (Micheal 21644370): cached server-side proxy for the
// public-link Google Sheets the dashboard pulls in the browser. Measured live:
// roster CSV 7-8.3s, supervisor targets 8.3s, live-riders poll ~1s per user per
// minute. A same-origin worker fetch from a CF datacenter is much faster, and
// the Cache API shares one upstream fetch across all users. Cache API only —
// no D1 writes (writes are capped). Whitelisted sheets/gids, session required.
const SHEET_PROXY_ALLOWED = {
  '1_80LVAdt68HgKKvODqDZeIo29zVTxNb2fzJh6xmUfD8': new Set(['0', '1584356034']), // الاداء + التارجت - read-only, Micheal 26 Nov
  '1OLvK2_Wi7k8jTa9K1FdLkNjQwpMD5ntMsG_pC8woTlk': new Set(['524668708']),
  '1qF6mEtqiDqejBupRYfK3zyODlRWYuNdBoDzrqB977O8': new Set(['1803561038']), // نتائج السحب: عمود AG الاستقطاعات - read-only, Micheal 21910622
};
async function handleSheetProxy(request, env, json, url, ctx) {
  if (url.pathname !== '/api/sheet/csv' || request.method !== 'GET') return null;
  const user = await getSessionUser(env, request);
  if (!user) return json({ error: 'unauthorized' }, 401);
  const id = String(url.searchParams.get('id') || '');
  const gid = String(url.searchParams.get('gid') || '');
  if (!SHEET_PROXY_ALLOWED[id] || !SHEET_PROXY_ALLOWED[id].has(gid)) return json({ error: 'not_allowed' }, 403);
  const ttlMs = Math.min(Math.max(parseInt(url.searchParams.get('ttl') || '120', 10) || 120, 15), 600) * 1000;
  const cache = caches.default;
  const cacheKey = new Request('https://sheet-cache.internal/' + id + '/' + gid);
  // Workers responses are not auto-compressed by Cloudflare (assets are, API responses are not -
  // measured live: the 38MB roster CSV crossed uncompressed). Gzip once at store time; hits just
  // pipe the stored bytes. If compression ever throws (CPU limits), the plain path still works.
  const gzipBuf = async (text) => await new Response(new Blob([text]).stream().pipeThrough(new CompressionStream('gzip'))).arrayBuffer();
  const wantsGzip = /(?:^|[,\s])gzip(?:[,\s;]|$)/i.test(request.headers.get('Accept-Encoding') || '');
  const serve = (text, how) => new Response(text, {
    status: 200,
    headers: { 'Content-Type': 'text/csv; charset=utf-8', 'Cache-Control': 'no-store', 'X-Sheet-Cache': how },
  });
  const serveGz = (buf, how) => new Response(buf, {
    status: 200,
    headers: { 'Content-Type': 'text/csv; charset=utf-8', 'Cache-Control': 'no-store', 'X-Sheet-Cache': how, 'Content-Encoding': 'gzip', 'Vary': 'Accept-Encoding' },
  });
  const fetchGoogle = async () => {
    const g = await fetch('https://docs.google.com/spreadsheets/d/' + id + '/gviz/tq?tqx=out:csv&gid=' + encodeURIComponent(gid), { signal: AbortSignal.timeout(20000) });
    if (!g.ok) throw new Error('upstream_' + g.status);
    const text = await g.text();
    if (text.trimStart().startsWith('<')) throw new Error('upstream_html');
    return text;
  };
  // Cache stores PLAIN text only. The 26 Nov gzip-at-store design double-compressed
  // in production: the Cache API round-trip returns the stored bytes re-gzipped, so
  // clients got gzip(gzip(csv)) with one Content-Encoding header (live-verified).
  // Gzip is now done ON THE FLY at serve time, only for bodies small enough to fit
  // the free 10ms CPU budget (~1M chars ≈ a few ms; 2.8MB ded sheet stays plain;
  // 38MB roster blew the budget before - live 503 - so it stays plain too).
  // Serve PLAIN always. Live-verified 26 Nov: when this worker sets
  // Content-Encoding: gzip itself, the platform compresses the body AGAIN at
  // egress - clients receive gzip(gzip(csv)) with one header and silently fall
  // back. There is no safe self-gzip from this worker; keep everything plain.
  const store = async (text) => {
    await cache.put(cacheKey, new Response(text, { headers: { 'Cache-Control': 'public, max-age=600', 'x-cached-at': String(Date.now()) } }));
  };
  const serveText = async (text, how) => serve(text, how);
  const serveHit = async (hit, how) => {
    const buf = await hit.arrayBuffer();
    return serveText(new TextDecoder().decode(buf), how);
  };
  try {
    const hit = await cache.match(cacheKey);
    if (hit) {
      const age = Date.now() - parseInt(hit.headers.get('x-cached-at') || '0', 10);
      if (age >= 0 && age < ttlMs) return await serveHit(hit, 'hit');
      if (age < ttlMs * 10) {
        if (ctx && ctx.waitUntil) ctx.waitUntil(fetchGoogle().then(store).catch(() => {}));
        return await serveHit(hit, 'stale');
      }
    }
    const text = await fetchGoogle();
    const storeResp = new Response(text, { headers: { 'Cache-Control': 'public, max-age=600', 'x-cached-at': String(Date.now()) } });
    if (ctx && ctx.waitUntil) ctx.waitUntil(cache.put(cacheKey, storeResp).catch(() => {})); else await cache.put(cacheKey, storeResp).catch(() => {});
    return serveText(text, 'miss');
  } catch (e) {
    return json({ error: 'upstream_failed', detail: String(e && e.message || e).slice(0, 80) }, 502);
  }
}

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
      if (!e.last) e.last = { body: m.kind === 'image' ? '📷 صورة' : m.kind === 'voice' ? '🎤 فويس' : m.body, ts: m.ts, mine: m.from_u === user.u };
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
      if (!pairs.has(k)) pairs.set(k, { a, b, last: { body: m.kind === 'image' ? '📷 صورة' : m.kind === 'voice' ? '🎤 فويس' : String(m.body || '').slice(0, 80), ts: m.ts } });
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

  // Micheal 26 Nov (21177591): admin switches for chat photo/voice sending.
  if (p === '/api/chat/features' && request.method === 'GET') {
    return json({ features: await chatFeatures(env) });
  }
  if (p === '/api/chat/features' && request.method === 'POST') {
    if (user.r !== 'admin') return json({ error: 'forbidden' }, 403);
    let fbody = null; try { fbody = await request.json(); } catch (e) {}
    const cur = await chatFeatures(env);
    const photo = fbody && typeof fbody.photo === 'boolean' ? fbody.photo : cur.photo;
    const voice = fbody && typeof fbody.voice === 'boolean' ? fbody.voice : cur.voice;
    await env.DB.prepare("INSERT INTO settings(k,v) VALUES('chat_photo',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(photo ? '1' : '0').run();
    await env.DB.prepare("INSERT INTO settings(k,v) VALUES('chat_voice',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(voice ? '1' : '0').run();
    return json({ ok: true, features: { photo, voice } });
  }

  if (p === '/api/chat/send' && request.method === 'POST') {
    const wait = await rateLimit(env, 'chat:' + user.u, 30, 60000, 60000);
    if (wait) return json({ error: 'rate_limited', wait }, 429);
    let body = null;
    try { body = await request.json(); } catch (e) {}
    const peer = String(body && body.to || '').toLowerCase().slice(0, 60);
    const kind = body && (body.kind === 'image' || body.kind === 'voice') ? body.kind : 'text';
    if (kind !== 'text' && user.r !== 'admin') {
      // Admin switches (21177591): server-side enforcement, not just hidden buttons.
      const f = await chatFeatures(env);
      if (kind === 'image' && !f.photo) return json({ error: 'photos_disabled' }, 403);
      if (kind === 'voice' && !f.voice) return json({ error: 'voice_disabled' }, 403);
    }
    const text = String(body && body.body || '').trim();
    if (kind === 'image') {
      // Images are small data-URLs compressed client-side, stored in D1 (free tier).
      if (!/^data:image\/(jpeg|png|webp);base64,/.test(text) || text.length > 500000) return json({ error: 'bad_image' }, 400);
    } else if (kind === 'voice') {
      // Voice notes (Micheal 25 Nov): short audio data-URLs (<=60s, compressed client-side),
      // stored in D1 like images. Optional ;dur=SECONDS media param carries the duration for display.
      // Cap stays far under D1's 2MB row limit; audio is never auto-deleted, same rule as images.
      if (!/^data:audio\/(webm|mp4|ogg|mpeg|aac|x-m4a)(;[\w=.+-]+)*;base64,/.test(text) || text.length < 500 || text.length > 700000) return json({ error: 'bad_voice' }, 400);
    } else if (!text || text.length > 1000) return json({ error: 'bad_message' }, 400);
    if (!peer || peer === user.u) return json({ error: 'bad_message' }, 400);
    const prow = await env.DB.prepare("SELECT u FROM users WHERE u=? AND status='active' AND r IN ('admin','manager','sup')").bind(peer).first();
    if (!prow) return json({ error: 'bad_peer' }, 400);
    const ts = Date.now();
    const r = await env.DB.prepare('INSERT INTO chat_messages(from_u,to_u,body,kind,ts) VALUES(?,?,?,?,?)').bind(user.u, peer, text, kind, ts).run();
    // APK push notification for the recipient (Micheal 24 Nov); never fail the send on it.
    try { await sendFcmToUser(env, peer, '💬 ' + user.n, kind === 'image' ? '📷 صورة' : kind === 'voice' ? '🎤 فويس' : text.slice(0, 100), ''); } catch (e) {}
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
  // sup/manager use it only while the admin leaves the eye on (Micheal 16458387);
  // everything else (delete/poll/report) stays admin-only
  const isShiftSide = isAdmin || user.r === 'sup' || user.r === 'manager';
  const shiftBlocked = !isAdmin && tabBlockedFor(await getHiddenTabs(env), 'shiftcmd', user);
  const now = Date.now();

  if (p === '/api/shiftcmd/submit' && request.method === 'POST') {
    if (!isShiftSide) return json({ error: 'forbidden' }, 403);
    if (shiftBlocked) return json({ error: 'tab_hidden' }, 403);
    const body = await request.json().catch(() => null);
    const f = body && body.payload;
    if (!f || typeof f !== 'object') return json({ error: 'missing_fields' }, 400);
    const action = String(f.action || '');
    if (!['extend', 'break', 'open'].includes(action)) return json({ error: 'bad_action' }, 400);
    const riderId = String(f.rider_id || '').replace(/[^0-9]/g, '');
    let city = String(f.city || '').trim();
    if (!isAdmin) {
      // a supervisor/zone manager can only command riders inside his own zone
      if (!user.s) return json({ error: 'forbidden' }, 403);
      city = user.s;
    }
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
    if (!isShiftSide) return json({ error: 'forbidden' }, 403);
    if (shiftBlocked) return json({ error: 'tab_hidden' }, 403);
    // the desktop heartbeat is read-only status (ts + app version) - every
    // shift-side role must see the same real state, otherwise supervisors
    // always read "offline" and their submissions get blocked (Micheal 16530778)
    const agentRow = await env.DB.prepare("SELECT v FROM settings WHERE k='shift_agent'").first();
    let agent = null;
    try { agent = agentRow ? JSON.parse(agentRow.v) : null; } catch (e) {}
    // non-admin sees only his own commands and commands targeting his zone
    const rows = isAdmin
      ? await env.DB.prepare('SELECT id,u,payload,status,result,ts,updated FROM shift_commands ORDER BY id DESC LIMIT 50').all()
      : await env.DB.prepare('SELECT id,u,payload,status,result,ts,updated FROM shift_commands WHERE u=? OR payload LIKE ? ORDER BY id DESC LIMIT 50')
          .bind(user.u, '%"city":"' + String(user.s || '') + '"%').all();
    return json({ commands: rows.results || [], agent });
  }

  if (p === '/api/shiftcmd/item' && request.method === 'GET') {
    if (!isShiftSide) return json({ error: 'forbidden' }, 403);
    if (shiftBlocked) return json({ error: 'tab_hidden' }, 403);
    const id = Number(url.searchParams.get('id') || 0);
    const r = await env.DB.prepare('SELECT id,u,payload,status,result,ts,updated FROM shift_commands WHERE id=?').bind(id).first();
    if (!r) return json({ error: 'not_found' }, 404);
    if (!isAdmin && r.u !== user.u && !String(r.payload || '').includes('"city":"' + String(user.s || '') + '"')) return json({ error: 'forbidden' }, 403);
    return json({ item: r });
  }

  // ---- Scheduled commands (26 Nov, admin only) ----
  if (p === '/api/shiftcmd/sched/list' && request.method === 'GET') {
    if (!isAdmin) return json({ error: 'forbidden' }, 403);
    const rows = await env.DB.prepare('SELECT * FROM shiftcmd_schedules ORDER BY time_hhmm, id').all();
    return json({ schedules: rows.results || [] });
  }

  if (p === '/api/shiftcmd/sched/add' && request.method === 'POST') {
    if (!isAdmin) return json({ error: 'forbidden' }, 403);
    const body = await request.json().catch(() => null) || {};
    const action = String(body.action || '');
    if (!['extend', 'break'].includes(action)) return json({ error: 'bad_action' }, 400);
    const target = String(body.target || 'codes');
    if (!['codes', 'break_all'].includes(target)) return json({ error: 'bad_target' }, 400);
    if (target === 'break_all' && action !== 'break') return json({ error: 'bad_target' }, 400);
    const time = String(body.time || '');
    if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(time)) return json({ error: 'bad_time' }, 400);
    const duration24 = String(body.duration24 || '').slice(0, 5);
    if (action === 'extend' && !/^([01]\d|2[0-3]):[0-5]\d$/.test(duration24)) return json({ error: 'bad_duration' }, 400);
    const codes = target === 'codes' ? String(body.codes || '').split(/[^0-9]+/).filter(Boolean).slice(0, 50).join(' ') : '';
    if (target === 'codes' && !codes) return json({ error: 'no_codes' }, 400);
    const city = target === 'codes' ? String(body.city || '').trim() : String(body.city || '').trim();
    if (target === 'codes' && !city) return json({ error: 'missing_city' }, 400);
    const reason = String(body.reason || '').slice(0, 60);
    if (action === 'break' && target === 'break_all' && !reason) return json({ error: 'bad_reason' }, 400); // Alex riders need it
    if (action === 'break' && target === 'codes' && city === 'الإسكندرية' && !reason) return json({ error: 'bad_reason' }, 400);
    const daily = body.daily === false ? 0 : 1;
    // If today's time already passed, mark today as run so the first fire is tomorrow
    // (a one-shot whose time passed is rejected - it would never fire).
    const { day, hm } = cairoNowParts();
    let lastRun = '';
    if (time <= hm) {
      if (!daily) return json({ error: 'time_passed' }, 400);
      lastRun = day;
    }
    const ins = await env.DB.prepare('INSERT INTO shiftcmd_schedules(action,target,codes,city,duration24,reason,vehicle,time_hhmm,daily,enabled,by_u,by_name,last_run,created) VALUES(?,?,?,?,?,?,?,?,?,1,?,?,?,?)')
      .bind(action, target, codes, city, duration24, reason, String(body.vehicle || '').slice(0, 30), time, daily, user.u, user.n || user.u, lastRun, now).run();
    return json({ ok: true, id: ins.meta.last_row_id });
  }

  if (p === '/api/shiftcmd/sched/del' && request.method === 'POST') {
    if (!isAdmin) return json({ error: 'forbidden' }, 403);
    const body = await request.json().catch(() => null) || {};
    await env.DB.prepare('DELETE FROM shiftcmd_schedules WHERE id=?').bind(Number(body.id || 0)).run();
    return json({ ok: true });
  }

  if (p === '/api/shiftcmd/sched/toggle' && request.method === 'POST') {
    if (!isAdmin) return json({ error: 'forbidden' }, 403);
    const body = await request.json().catch(() => null) || {};
    const id = Number(body.id || 0);
    const en = body.enabled ? 1 : 0;
    // re-enabling a schedule whose time already passed today starts it tomorrow.
    const { day, hm } = cairoNowParts();
    const r = await env.DB.prepare('SELECT time_hhmm FROM shiftcmd_schedules WHERE id=?').bind(id).first();
    if (!r) return json({ error: 'not_found' }, 404);
    const lastRun = (en && String(r.time_hhmm) <= hm) ? day : '';
    await env.DB.prepare('UPDATE shiftcmd_schedules SET enabled=?, last_run=? WHERE id=?').bind(en, lastRun, id).run();
    return json({ ok: true });
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
    // Batch claim (Micheal 25 Nov): same action + same form group, one run, per-command results.
    // Only for desktops >= 0.3.37 (older ones get the single-job shape they understand).
    const ge = (v, a) => { const p = String(v || '').split('.').map(Number), q = a.split('.').map(Number); for (let i = 0; i < 3; i++) { if ((p[i] || 0) > (q[i] || 0)) return true; if ((p[i] || 0) < (q[i] || 0)) return false; } return true; };
    let jobs = [{ id: s.id, payload: JSON.parse(s.payload) }];
    if (ge(pv, '0.3.37')) {
      const grp = (p) => (p.city === '\u0627\u0644\u0625\u0633\u0643\u0646\u062f\u0631\u064a\u0629' && p.action !== 'open') ? 'alex' : 'delta';
      const a0 = jobs[0].payload.action, g0 = grp(jobs[0].payload);
      const rows = await env.DB.prepare("SELECT * FROM shift_commands WHERE status='pending' ORDER BY id LIMIT 12").all();
      jobs = [];
      for (const r of rows.results || []) {
        let p; try { p = JSON.parse(r.payload); } catch (e) { continue; }
        if (p.action === a0 && grp(p) === g0 && jobs.length < 8) jobs.push({ id: r.id, payload: p });
      }
    }
    for (const b of jobs) await env.DB.prepare("UPDATE shift_commands SET status='claimed',updated=? WHERE id=? AND status='pending'").bind(now, b.id).run();
    return json({ job: { kind: 'shift', id: jobs[0].id, payload: jobs[0].payload, jobs } });
  }
  const r = await env.DB.prepare("SELECT * FROM hiring_requests WHERE status='approved' ORDER BY id LIMIT 1").first();
  if (!r) return json({ job: null });
  await env.DB.prepare("UPDATE hiring_requests SET status='claimed',updated=? WHERE id=? AND status='approved'").bind(now, r.id).run();
  const imgs = await env.DB.prepare('SELECT k,data FROM hiring_images WHERE request_id=?').bind(r.id).all();
  const images = {};
  for (const x of imgs.results || []) images[x.k] = x.data;
  return json({ job: { kind: 'hiring', id: r.id, u: r.u, payload: JSON.parse(r.payload), images } });
}

async function legalHistory(env, caseId, status, note, user) {
  await env.DB.prepare('INSERT INTO legal_case_history(case_id,status,note,by_u,by_name,ts) VALUES(?,?,?,?,?,?)').bind(caseId, status, String(note || ''), user.u, user.n, Date.now()).run();
}

// شئون قانونية (Micheal 25 Nov): supervisors submit rider cases with a receipt photo;
// the legal officer moves statuses; supervisors can only mark their own case as paid.
// Receipt images live in D1 and are served owner-or-legal-or-admin only (never public).
async function handleLegal(request, env, json, url) {
  const p = url.pathname;
  const user = await getSessionUser(env, request);
  if (!user) return json({ error: 'unauthorized' }, 401);
  if (user.r !== 'legal' && tabBlockedFor(await getHiddenTabs(env), 'legal', user)) return json({ error: 'tab_hidden' }, 403);
  const isLegal = user.r === 'legal' || user.r === 'admin';
  const isSupSide = ['admin', 'manager', 'sup'].includes(user.r);
  const now = Date.now();
  const LIST_COLS = 'id,rider_id,rider_name,national_id,amount,phone,phone2,city,u,u_name,status,case_number,settle_amount,judgment_status,judgment_detail,judgment_amount,created,updated';

  if (p === '/api/legal/submit' && request.method === 'POST') {
    if (!isSupSide) return json({ error: 'forbidden' }, 403);
    const wait = await rateLimit(env, 'legal:' + user.u, 10, 60 * 60 * 1000, 60 * 1000);
    if (wait) return json({ error: 'locked', wait }, 429);
    const body = await request.json().catch(() => null);
    if (!body) return json({ error: 'missing_fields' }, 400);
    const t = (v, n) => String(v || '').trim().slice(0, n);
    const digits = (v, n) => String(v || '').replace(/[٠-٩]/g, (c) => '٠١٢٣٤٥٦٧٨٩'.indexOf(c)).replace(/\D/g, '').slice(0, n);
    const riderId = digits(body.rider_id, 12);
    const name = t(body.rider_name, 160);
    const nid = digits(body.national_id, 14);
    const amount = digits(body.amount, 9);
    const phone = cleanContact.phone(body.phone || '');
    const phone2 = cleanContact.phone(body.phone2 || '');
    const city = t(body.city, 80);
    if (!riderId || !name || nid.length !== 14 || !amount || !phone) return json({ error: 'missing_fields' }, 400);
    const img = typeof body.receipt === 'string' ? body.receipt : '';
    if (!/^data:image\/(jpeg|png|webp);base64,/.test(img) || img.length > 500000) return json({ error: 'bad_image' }, 400);
    const ins = await env.DB.prepare("INSERT INTO legal_cases(rider_id,rider_name,national_id,amount,phone,phone2,city,u,u_name,status,created,updated) VALUES(?,?,?,?,?,?,?,?,?,'received',?,?)").bind(riderId, name, nid, amount, phone, phone2, city, user.u, user.n, now, now).run();
    const cid = ins.meta.last_row_id;
    await env.DB.prepare('INSERT INTO legal_case_images(case_id,k,data) VALUES(?,?,?)').bind(cid, 'receipt', img).run();
    // National-ID front (Micheal 25 Nov, msg 16641143): optional second upload, same validation.
    const nidImg = typeof body.nid_front === 'string' ? body.nid_front : '';
    // Required like the receipt (Micheal 16644969).
    if (!/^data:image\/(jpeg|png|webp);base64,/.test(nidImg) || nidImg.length > 500000) return json({ error: 'bad_image' }, 400);
    await env.DB.prepare('INSERT INTO legal_case_images(case_id,k,data) VALUES(?,?,?)').bind(cid, 'nid_front', nidImg).run();
    await legalHistory(env, cid, 'received', '', user);
    return json({ ok: true, id: cid });
  }

  // Reminder (Micheal 25 Nov, msg 16732996): sup/manager/admin pings the legal officer about a case.
  // One outstanding reminder per case; legal sees who/when on the card + detail; opening the detail marks it seen.
  if (p === '/api/legal/remind' && request.method === 'POST') {
    if (user.r === 'legal') return json({ error: 'forbidden' }, 403);
    if (!isSupSide) return json({ error: 'forbidden' }, 403);
    const wait = await rateLimit(env, 'legalremind:' + user.u, 20, 60 * 60 * 1000, 60 * 1000);
    if (wait) return json({ error: 'locked', wait }, 429);
    const body = await request.json().catch(() => null);
    const cid = Number(body && body.id || 0);
    const r = await env.DB.prepare('SELECT id,rider_id,rider_name,u FROM legal_cases WHERE id=?').bind(cid).first();
    if (!r) return json({ error: 'not_found' }, 404);
    if (user.r === 'sup' && r.u !== user.u) return json({ error: 'forbidden' }, 403);
    const now = Date.now();
    await env.DB.prepare('INSERT INTO legal_reminders(case_id,by_u,by_name,ts,seen) VALUES(?,?,?,?,0) ON CONFLICT(case_id) DO UPDATE SET by_u=excluded.by_u, by_name=excluded.by_name, ts=excluded.ts, seen=0').bind(cid, user.u, user.n || user.u, now).run();
    const legals = await env.DB.prepare("SELECT u FROM users WHERE r='legal' AND status='active'").all();
    for (const lg of (legals.results || [])) {
      await insertNotification(env, lg.u, '🔔 تذكير بخصوص حالة', 'المندوب ' + r.rider_name + ' (' + r.rider_id + ') — حالة #' + r.id + ' — تذكير من ' + (user.n || user.u), String(r.rider_id || ''));
    }
    return json({ ok: true, ts: now });
  }

  if (p === '/api/legal/list' && request.method === 'GET') {
    let rows;
    if (isLegal) rows = (await env.DB.prepare('SELECT ' + LIST_COLS + ' FROM legal_cases ORDER BY id DESC LIMIT 300').all()).results || [];
    else if (isSupSide) rows = (await env.DB.prepare('SELECT ' + LIST_COLS + ' FROM legal_cases WHERE u=? ORDER BY id DESC LIMIT 300').bind(user.u).all()).results || [];
    else return json({ error: 'forbidden' }, 403);
    const st = String(url.searchParams.get('status') || '');
    const q = String(url.searchParams.get('q') || '').replace(/\D/g, '').slice(0, 14);
    if (st) rows = rows.filter((r) => r.status === st);
    if (q) rows = rows.filter((r) => String(r.national_id).includes(q) || String(r.rider_id).includes(q));
    if (rows.length) {
      const rems = await env.DB.prepare('SELECT case_id,by_name,ts FROM legal_reminders WHERE seen=0').all();
      const rmap = {};
      for (const x of rems.results || []) rmap[x.case_id] = { by_name: x.by_name, ts: x.ts };
      for (const r of rows) if (rmap[r.id]) r.reminder = rmap[r.id];
    }
    return json({ cases: rows });
  }

  if (p === '/api/legal/item' && request.method === 'GET') {
    const id = Number(url.searchParams.get('id') || 0);
    const r = await env.DB.prepare('SELECT * FROM legal_cases WHERE id=?').bind(id).first();
    if (!r) return json({ error: 'not_found' }, 404);
    if (!isLegal && r.u !== user.u) return json({ error: 'forbidden' }, 403);
    const rem = await env.DB.prepare('SELECT by_name,ts,seen FROM legal_reminders WHERE case_id=?').bind(id).first();
    if (rem && user.r === 'legal' && !rem.seen) await env.DB.prepare('UPDATE legal_reminders SET seen=1 WHERE case_id=?').bind(id).run();
    const imgs = await env.DB.prepare('SELECT k,data FROM legal_case_images WHERE case_id=?').bind(id).all();
    const images = {};
    for (const x of imgs.results || []) images[x.k] = x.data;
    const hist = await env.DB.prepare('SELECT status,note,by_name,ts FROM legal_case_history WHERE case_id=? ORDER BY id').bind(id).all();
    return json({ item: r, images, history: hist.results || [], reminder: rem && !rem.seen ? { by_name: rem.by_name, ts: rem.ts } : null });
  }

  if (p === '/api/legal/status' && request.method === 'POST') {
    const body = await request.json().catch(() => null);
    const id = Number((body && body.id) || 0);
    const r = await env.DB.prepare('SELECT * FROM legal_cases WHERE id=?').bind(id).first();
    if (!r) return json({ error: 'not_found' }, 404);
    if (r.status === 'closed') return json({ error: 'case_closed' }, 409); // closed = view-only, rejects every edit (Micheal 16408616)
    const st = String((body && body.status) || '');
    if (!['received', 'contacted', 'paid', 'filed', 'judgment', 'closed'].includes(st)) return json({ error: 'bad_status' }, 400);
    if (isLegal) { /* the legal officer (or admin) moves any status, including the new contacted + closed steps */ }
    else if (isSupSide && r.u === user.u && st === 'paid') { /* supervisor reports their own rider paid */ }
    else return json({ error: 'forbidden' }, 403);
    // after سداد every checkbox is locked; only the settlement amount stays editable, legal side only
    if (r.status === 'paid' && !(isLegal && st === 'paid')) return json({ error: 'paid_locked' }, 409);
    const tn = (v, n) => String(v || '').trim().slice(0, n);
    const settle = isLegal && body.settle_amount !== undefined
      ? String(body.settle_amount || '').replace(/[٠-٩]/g, (c) => '٠١٢٣٤٥٦٧٨٩'.indexOf(c)).replace(/\D/g, '').slice(0, 9)
      : r.settle_amount;
    await env.DB.prepare('UPDATE legal_cases SET status=?,case_number=?,settle_amount=?,judgment_status=?,judgment_detail=?,judgment_amount=?,updated=? WHERE id=?')
      .bind(st, st === 'filed' ? tn(body.case_number, 60) : r.case_number, settle, st === 'judgment' ? tn(body.judgment_status, 120) : r.judgment_status,
        st === 'judgment' ? tn(body.judgment_detail, 500) : r.judgment_detail, st === 'judgment' ? tn(body.judgment_amount, 30) : r.judgment_amount, Date.now(), id).run();
    await legalHistory(env, id, st, tn(body && body.note, 300), user);
    return json({ ok: true });
  }

  if (p === '/api/legal/delete' && request.method === 'POST') {
    // admin or the legal officer (duplicates / resubmit requests, Micheal 16411808); a snapshot log survives the delete
    if (user.r !== 'admin' && user.r !== 'legal') return json({ error: 'forbidden' }, 403);
    const body = await request.json().catch(() => null);
    const id = Number((body && body.id) || 0);
    const r = await env.DB.prepare('SELECT * FROM legal_cases WHERE id=?').bind(id).first();
    if (r) await env.DB.prepare('INSERT INTO legal_case_deletes(case_id,snapshot,by_u,by_name,ts) VALUES(?,?,?,?,?)').bind(id, JSON.stringify(r).slice(0, 4000), user.u, user.n, Date.now()).run();
    await env.DB.prepare('DELETE FROM legal_cases WHERE id=?').bind(id).run();
    await env.DB.prepare('DELETE FROM legal_case_images WHERE case_id=?').bind(id).run();
    await env.DB.prepare('DELETE FROM legal_case_history WHERE case_id=?').bind(id).run();
    return json({ ok: true });
  }

  return null;
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
    const channel = 'email'; // fixed: login codes always go to Gmail (Micheal 16318052)
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
    const channel = 'email'; // fixed: login codes always go to Gmail (Micheal 16318052)
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
    const channel = 'email'; // fixed: login codes always go to Gmail (Micheal 16318052)
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
      const r = ['admin', 'manager', 'sup', 'monitor', 'viewer', 'legal'].includes(body.r) ? body.r : 'sup';
      const s = ['admin', 'monitor', 'legal'].includes(r) ? '' : String(body.s || '').slice(0, 120);
      const n = String(body.n || u).slice(0, 120);
      if (!u) return json({ error: 'invalid_username' }, 400);
      let emailUpd = null;
      if (body.email !== undefined) {
        const em = String(body.email || '').trim();
        emailUpd = em ? cleanContact.email(em) : '';
        if (em && !emailUpd) return json({ error: 'invalid_email' }, 400);
      }
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
        if (emailUpd !== null) await env.DB.prepare('UPDATE users SET email=?, updated_at=? WHERE u=?').bind(emailUpd, Date.now(), u).run();
        if (body.p) await env.DB.prepare('UPDATE users SET n=?, r=?, s=?, h=?, updated_at=? WHERE u=?').bind(n, r, s, await hp2new(u, String(body.p)), Date.now(), u).run();
        else await env.DB.prepare('UPDATE users SET n=?, r=?, s=?, updated_at=? WHERE u=?').bind(n, r, s, Date.now(), u).run();
        return json({ ok: true });
      }
      const p2 = body.p ? String(body.p) : randPassword();
      await env.DB.prepare('INSERT INTO users(u,n,r,s,h,email,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)')
        .bind(u, n, r, s, await hp2new(u, p2), emailUpd || '', 'active', Date.now(), Date.now()).run();
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
      const r = ['admin', 'manager', 'sup', 'monitor', 'viewer', 'legal'].includes(body.r) ? body.r : 'sup';
      const s = ['admin', 'monitor', 'viewer', 'legal'].includes(r) ? '' : String(body.s || '').slice(0, 120);
      if (!['admin', 'monitor', 'viewer', 'legal'].includes(r) && !s) return json({ error: 'missing_fields' }, 400);
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


/* ---------------- تقارير المشرفين بالإيميل (Micheal 25 Nov) ----------------
   الأدمن يختار نوع التقرير واليوم، والسيرفر يسحب نفس شيت الأداء، يفلتر كل
   مشرف على مناديبه بس، يبني ملف Excel ويبعته على إيميله. التقييد بيتم
   هنا على السيرفر — ملف كل مشرف فيه مناديبه بس (مفيش طريقة من الكلاينت
   توصل لبيانات مشرف تاني). المطابقة اسم-لحساب بالتطبيع الكامل بس (مفيش
   تخمين جزئي: التقرير فيه بيانات، والغلط هنا = تسريب لمشرف تاني). */
const PERF_SHEET_ID = '1_80LVAdt68HgKKvODqDZeIo29zVTxNb2fzJh6xmUfD8';
const REPORT_TYPES = { perf: 'أداء المناديب', wallets: 'المحافظ', contracts: 'انتهاء العقود', deductions: 'الاستقطاعات' };
const _repUse = new Map(); // day:username -> count (in-memory rate limit, كفاية لزرار يدوي)

function repNameKey(value) {
  return String(value || '').normalize('NFKC')
    .replace(/[ً-ٰٟـ]/g, '')
    .replace(/[أإآٱ]/g, 'ا').replace(/ى/g, 'ي')
    .replace(/[‎‏‪-‮]/g, '')
    .replace(/\s+/g, ' ').trim().toLocaleLowerCase('ar');
}

// نفس منطق pd() في index.html: تواريخ الشيت جاية نص m/d/y أو d-m-y أو y-m-d
function repNormDay(s) {
  if (!s) return '';
  s = String(s).trim().split(' ')[0];
  let d, m, y, p;
  if (s.includes('/')) { p = s.split('/'); if (p.length < 3) return ''; m = +p[0]; d = +p[1]; y = +p[2]; if (m > 12 && d <= 12) { const t = m; m = d; d = t; } }
  else if (s.includes('-')) { p = s.split('-'); if (p.length < 3) return ''; if (p[0].length === 4) { y = +p[0]; m = +p[1]; d = +p[2]; } else { d = +p[0]; m = +p[1]; y = +p[2]; } }
  else return '';
  if (!y || !m || !d || m > 12 || d > 31) return '';
  if (y < 100) y += 2000;
  return y + '-' + String(m).padStart(2, '0') + '-' + String(d).padStart(2, '0');
}

function repVehicle(name) {
  const n = String(name || '').trim();
  if (/(?:^|[^A-Z0-9])WLK(?:$|[^A-Z0-9])/i.test(n)) return 'WLK';
  if (/(?:^|[^A-Z0-9])BC(?:$|[^A-Z0-9])/i.test(n)) return 'عجلة';
  return 'مكنة';
}

const HC_GID = '2127591673'; // شيت الهيدكاونت: صف واحد لكل مندوب (محفظة + عقد + حالة + مشرف) — مصدر المحافظ والعقود
// أداء يوم واحد بس: فلترة عند جوجل نفسها (بدل ما نسحب الشيت كله ~40MB ونتجاوز حد CPU المجاني).
// ملحوظة: gviz out:csv بيطبّق where لكن بيرجّع كل الأعمدة بترتيبها الأصلي — القراءة بالأعمدة الأصلية.
// gviz ساعات بيرجع HTTP 200 مع صفحة خطأ HTML بدل الـ CSV (ضغط/ريت ليميت) — من غير فحص كانت بتطلع
// نتيجة فاضية صامتة (باج Micheal 25 Nov: "التاريخ غلط" ومعاينة فاضية). الفحص: صف الهيدر لازم يبدأ بالعمود المتوقع، ولو لأ نعيد المحاولة مرة وبعدين نرمي خطأ واضح.
async function repFetchCsv(url, expectHeader) {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const res = await fetch(url + '&_=' + Date.now());
      if (!res.ok) continue;
      const rows = parseCsv(await res.text());
      if (rows.length && String(rows[0][0] || '').trim() === expectHeader) return rows.slice(1);
    } catch (e) {}
  }
  throw new Error('sheet_fetch_failed');
}
async function repFetchPerfRange(d1, d2) {
  const q = encodeURIComponent("select * where F >= date '" + d1 + "' and F <= date '" + d2 + "'");
  return repFetchCsv('https://docs.google.com/spreadsheets/d/' + PERF_SHEET_ID + '/gviz/tq?tqx=out:csv&gid=0&headers=1&tq=' + q, 'rider_id');
}
async function repFetchHc() {
  return repFetchCsv('https://docs.google.com/spreadsheets/d/' + PERF_SHEET_ID + '/gviz/tq?tqx=out:csv&gid=' + HC_GID + '&headers=1', 'ID المندوب');
}
async function repLatestDay() {
  try {
    const rows = await repFetchCsv('https://docs.google.com/spreadsheets/d/' + PERF_SHEET_ID + '/gviz/tq?tqx=out:csv&gid=0&headers=1&tq=' + encodeURIComponent('select max(F)'), 'max التاريخ');
    return repNormDay(rows[0] && rows[0][0]);
  } catch (e) { return ''; }
}

/* الاستقطاعات في تقارير المشرفين (Micheal 26 Nov): نفس مصدر جدول «استقطاعات المشرفين» في اللوحة —
   تابة «نتائج السحب» في شيت القبض (عمود AG)، آخر (سنة،شهر) مجموع استقطاعاته مش صفر، والمشرف من هيدكاونت شيت القبض.
   القراءة بالهيدر مش بأرقام الأعمدة عشان إدخال عمود جديد في الشيت مايكسرش التقرير. */
const REP_PAY_SHEET_ID = '1qF6mEtqiDqejBupRYfK3zyODlRWYuNdBoDzrqB977O8';
const REP_SAHB_GID = '1803561038', REP_PAY_HC_GID = '1378991698';
function repHeaderKey(s) {
  return String(s || '').normalize('NFKC')
    .replace(/[ً-ٰٟـ]/g, '')
    .replace(/[أإآٱ]/g, 'ا').replace(/ى/g, 'ي')
    .replace(/[‎‏‪-‮]/g, '')
    .replace(/\s+/g, '').trim().toLocaleLowerCase('ar');
}
// gviz CSV بيرجّع الأرقام منسّقة بالشكل العربي (فاصلة عشرية ٫ وفاصل آلاف ٬ وأحيانًا أرقام هندية) — parseFloat العادي كان بيقص الكسور
function repNum(v) {
  const t = String(v == null ? '' : v).replace(/[٠-٩]/g, d => String(d.charCodeAt(0) - 1632)).replace(/[٬,\s]/g, '').replace(/٫/g, '.');
  const n = parseFloat(t);
  return isFinite(n) ? n : 0;
}
async function repFetchDedLatest() {
  // آخر (سنة،شهر) فيه استقطاعات فعلية — نفس منطق اللوحة عشان التقرير يطابق اللي المدير شايفه
  const monthRows = await repFetchCsv('https://docs.google.com/spreadsheets/d/' + REP_PAY_SHEET_ID + '/gviz/tq?tqx=out:csv&gid=' + REP_SAHB_GID + '&headers=1&tq=' + encodeURIComponent('select AY, AZ, sum(AG) group by AY, AZ'), 'Month');
  let pick = null;
  for (const r of monthRows) {
    const mo = repNum(r[0]), y = repNum(r[1]), s = Math.abs(repNum(r[2]));
    if (!mo || !y || !s) continue;
    if (!pick || y * 100 + mo > pick.y * 100 + pick.mo) pick = { y, mo };
  }
  const hcRows = await repFetchCsv('https://docs.google.com/spreadsheets/d/' + REP_PAY_SHEET_ID + '/gviz/tq?tqx=out:csv&gid=' + REP_PAY_HC_GID + '&headers=1', 'ID');
  const hcSup = new Map(); // كود المندوب -> اسم المشرف (هيدكاونت شيت القبض، نفس مصدر جدول اللوحة)
  for (const r of hcRows) {
    const id = String(r[0] || '').trim();
    if (id && !hcSup.has(id)) hcSup.set(id, String(r[2] || '').trim());
  }
  const byId = new Map(), weeks = new Map();
  if (pick) {
    const q = 'select * where AY = ' + pick.mo + ' and AZ = ' + pick.y;
    const rows = await repFetchCsv('https://docs.google.com/spreadsheets/d/' + REP_PAY_SHEET_ID + '/gviz/tq?tqx=out:csv&gid=' + REP_SAHB_GID + '&headers=1&tq=' + encodeURIComponent(q), 'كود الطيار');
    // أول صف في النتيجة هو الهيدر — repFetchCsv شاله، فبنستنتج الأعمدة من مواقعها الثابتة في نتائج السحب
    for (const r of rows) {
      const id = String(r[0] || '').trim();
      if (!id) continue;
      const amt = Math.abs(repNum(r[32]));
      if (!amt) continue;
      const wRaw = String(r[49] || '').trim();
      const wm = wRaw.match(/(\d+)/), wOrder = /last/i.test(wRaw) ? 99 : (wm ? +wm[1] : 50);
      if (!weeks.has(wOrder)) weeks.set(wOrder, wRaw || ('Week ' + wOrder));
      let x = byId.get(id);
      if (!x) { x = { id, name: String(r[1] || '').trim(), weeks: new Map(), total: 0 }; byId.set(id, x); }
      x.weeks.set(wOrder, (x.weeks.get(wOrder) || 0) + amt);
      x.total += amt;
    }
  }
  const weekList = [...weeks.keys()].sort((a, b) => a - b).map(k => ({ key: k, label: weeks.get(k) }));
  return { byId, weekList, hcSup, month: pick };
}

/* ---- مولّد Excel بسيط: ZIP تخزين مباشر (من غير ضغط) + XML جداول ----
   مفيش npm جوّه الـ Worker، فالملف بيتبني يدوي — صيغة xlsx قياسية بـ inline strings */
const REP_CRC_TABLE = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
function repCrc32(u8) { let c = 0xFFFFFFFF; for (let i = 0; i < u8.length; i++) c = REP_CRC_TABLE[(c ^ u8[i]) & 0xFF] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; }
function repZip(files) {
  const enc = new TextEncoder(), parts = [], central = []; let offset = 0;
  for (const f of files) {
    const name = enc.encode(f.name), data = f.data, crc = repCrc32(data);
    const lh = new DataView(new ArrayBuffer(30));
    lh.setUint32(0, 0x04034b50, true); lh.setUint16(4, 20, true); lh.setUint16(6, 0x0800, true);
    lh.setUint32(14, crc, true); lh.setUint32(18, data.length, true); lh.setUint32(22, data.length, true);
    lh.setUint16(26, name.length, true);
    parts.push(new Uint8Array(lh.buffer), name, data);
    const ch = new DataView(new ArrayBuffer(46));
    ch.setUint32(0, 0x02014b50, true); ch.setUint16(4, 20, true); ch.setUint16(6, 20, true); ch.setUint16(8, 0x0800, true);
    ch.setUint32(16, crc, true); ch.setUint32(20, data.length, true); ch.setUint32(24, data.length, true);
    ch.setUint16(28, name.length, true); ch.setUint32(42, offset, true);
    central.push(new Uint8Array(ch.buffer), name);
    offset += 30 + name.length + data.length;
  }
  let cdSize = 0; for (const c of central) cdSize += c.length;
  const eocd = new DataView(new ArrayBuffer(22));
  eocd.setUint32(0, 0x06054b50, true); eocd.setUint16(8, files.length, true); eocd.setUint16(10, files.length, true);
  eocd.setUint32(12, cdSize, true); eocd.setUint32(16, offset, true);
  const out = new Uint8Array(offset + cdSize + 22); let pos = 0;
  for (const pt of parts) { out.set(pt, pos); pos += pt.length; }
  for (const c of central) { out.set(c, pos); pos += c.length; }
  out.set(new Uint8Array(eocd.buffer), pos);
  return out;
}
function repXesc(s) { return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[c])); }
function repColName(i) { let s = ''; i++; while (i > 0) { const m = (i - 1) % 26; s = String.fromCharCode(65 + m) + s; i = Math.floor((i - 1) / 26); } return s; }
function repSheetXml(headers, rows) {
  const cell = (v, r, c) => {
    const ref = repColName(c) + r;
    if (typeof v === 'number' && isFinite(v)) return '<c r="' + ref + '"><v>' + Math.round(v * 100) / 100 + '</v></c>';
    return '<c r="' + ref + '" t="inlineStr"><is><t xml:space="preserve">' + repXesc(v == null ? '' : v) + '</t></is></c>';
  };
  let xml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>';
  xml += '<row r="1">' + headers.map((h, c) => cell(h, 1, c)).join('') + '</row>';
  rows.forEach((row, i) => { xml += '<row r="' + (i + 2) + '">' + row.map((v, c) => cell(v, i + 2, c)).join('') + '</row>'; });
  return xml + '</sheetData></worksheet>';
}
function repBuildXlsx(sheets) {
  const enc = new TextEncoder(), files = [];
  let types = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>';
  sheets.forEach((s, i) => { types += '<Override PartName="/xl/worksheets/sheet' + (i + 1) + '.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'; });
  files.push({ name: '[Content_Types].xml', data: enc.encode(types + '</Types>') });
  files.push({ name: '_rels/.rels', data: enc.encode('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>') });
  let wb = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>';
  sheets.forEach((s, i) => { wb += '<sheet name="' + repXesc(String(s.name).slice(0, 31)) + '" sheetId="' + (i + 1) + '" r:id="rId' + (i + 1) + '"/>'; });
  files.push({ name: 'xl/workbook.xml', data: enc.encode(wb + '</sheets></workbook>') });
  let rels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">';
  sheets.forEach((s, i) => { rels += '<Relationship Id="rId' + (i + 1) + '" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet' + (i + 1) + '.xml"/>'; });
  files.push({ name: 'xl/_rels/workbook.xml.rels', data: enc.encode(rels + '</Relationships>') });
  sheets.forEach((s, i) => { files.push({ name: 'xl/worksheets/sheet' + (i + 1) + '.xml', data: enc.encode(repSheetXml(s.headers, s.rows)) }); });
  return repZip(files);
}
function repU8ToB64(u8) { let s = ''; const CH = 0x8000; for (let i = 0; i < u8.length; i += CH) s += String.fromCharCode.apply(null, u8.subarray(i, i + CH)); return btoa(s); }

/* تجميع التقرير: يرجع لكل مشرف (بالاسم الظاهر في الشيت) ملفاته وعدّاداته.
   perf = صفوف اليوم المختار بس · wallets/contracts = آخر صف لكل مندوب لحد اليوم المختار */
async function repAssemble(env, types, d1, d2) {
  const bySup = new Map(); // nameKey -> { name, perf: Map(id->agg), hc: [] }
  const group = (name) => {
    const k = repNameKey(name);
    let g = bySup.get(k);
    if (!g) { g = { name: String(name || '').trim(), perf: new Map(), hc: [], ded: [] }; bySup.set(k, g); }
    return g;
  };
  let latestDay = '', perfRowCount = 0;
  const jobs = [];
  if (types.includes('perf')) jobs.push((async () => {
    for (const r of await repFetchPerfRange(d1, d2)) {
      const id = String(r[0] || '').trim(), s = String(r[6] || '').trim();
      if (!id || !s) continue;
      perfRowCount++;
      const g = group(s);
      let x = g.perf.get(id);
      if (!x) { x = { id, o: 0, a: 0, p: 0, b: 0, n: '', z: '', bt: '', lt: '' }; g.perf.set(id, x); }
      x.o += parseInt(r[4]) || 0; x.a += +r[2] || 0; x.p += +r[1] || 0; x.b += +r[3] || 0;
      const rd = repNormDay(r[5]);
      if (rd >= x.lt) { x.lt = rd; x.n = String(r[8] || '').trim() || x.n; x.z = String(r[10] || '').trim() || x.z; x.bt = String(r[13] || '').trim() || x.bt; }
    }
  })());
  if (types.includes('wallets') || types.includes('contracts')) jobs.push((async () => {
    for (const r of await repFetchHc()) {
      const id = String(r[0] || '').trim(), s = String(r[9] || '').trim();
      if (!id || !s) continue;
      group(s).hc.push({ id, n: String(r[1] || '').trim(), bt: String(r[2] || '').trim(), st: String(r[5] || '').trim(), e: String(r[7] || '').trim(), w: parseFloat(String(r[10] || '0').replace(/,/g, '')) || 0 });
    }
  })());
  jobs.push((async () => { latestDay = await repLatestDay(); })());
  let dedData = null;
  if (types.includes('deductions')) jobs.push((async () => {
    dedData = await repFetchDedLatest();
    for (const d of dedData.byId.values()) {
      const supName = dedData.hcSup.get(d.id) || '';
      if (!supName) continue; // مندوب مش في الهيدكاونت — مينفعش نخمّن مشرفه في تقرير بيتبعت إيميل
      group(supName).ded.push(d);
    }
  })());
  await Promise.all(jobs);
  const dayMs = Date.parse(cairoDay() + 'T00:00:00Z'); // المحافظ/العقود حالة حالية — مش مرتبطة بفترة الأداء
  const files = new Map(); // nameKey -> { name, riders, sheets: [{name,headers,rows}] }
  for (const [k, g] of bySup) {
    const sheets = [];
    if (types.includes('perf')) {
      const list = [...g.perf.values()].sort((x, y) => y.o - x.o);
      sheets.push({
        name: REPORT_TYPES.perf,
        headers: ['الكود', 'الاسم', 'المنطقة', 'الباتش', 'المركبة', 'الطلبات', 'الساعات الفعلية', 'الساعات المخططة', 'نسبة الالتزام %', 'طلب/ساعة', 'الراحة'],
        rows: list.map(x => [x.id, x.n, x.z, x.bt, repVehicle(x.n), x.o, x.a, x.p, x.p ? x.a / x.p * 100 : 0, x.a ? x.o / x.a : 0, x.b]),
      });
    }
    if (types.includes('wallets')) {
      const list = g.hc.slice().sort((x, y) => x.w - y.w);
      sheets.push({
        name: REPORT_TYPES.wallets,
        headers: ['الكود', 'الاسم', 'الحالة', 'الباتش', 'المحفظة'],
        rows: list.map(x => [x.id, x.n, x.st, x.bt, Math.round(x.w * 100) / 100]),
      });
    }
    if (types.includes('contracts')) {
      const list = g.hc.filter(x => x.e && x.st !== 'إقالة').map(x => {
        const left = Math.ceil((Date.parse(x.e + 'T00:00:00Z') - dayMs) / 86400000);
        return { x, left };
      }).sort((a, b) => a.left - b.left);
      sheets.push({
        name: REPORT_TYPES.contracts,
        headers: ['الكود', 'الاسم', 'الحالة', 'نهاية العقد', 'الأيام المتبقية'],
        rows: list.map(({ x, left }) => [x.id, x.n, x.st, x.e, left]),
      });
    }
    if (types.includes('deductions') && dedData) {
      const wks = dedData.weekList;
      const list = g.ded.slice().sort((x, y) => y.total - x.total);
      const body = list.map(x => [x.id, x.name, ...wks.map(w => { const v = x.weeks.get(w.key); return v ? Math.round(v * 100) / 100 : ''; }), Math.round(x.total * 100) / 100]);
      if (list.length) {
        const weekSums = wks.map(w => Math.round(list.reduce((s, x) => s + (x.weeks.get(w.key) || 0), 0) * 100) / 100);
        body.push(['', 'الإجمالي', ...weekSums, Math.round(list.reduce((s, x) => s + x.total, 0) * 100) / 100]);
      }
      sheets.push({
        name: REPORT_TYPES.deductions,
        headers: ['الكود', 'الاسم', ...wks.map(w => w.label), 'الإجمالي'],
        rows: body,
      });
    }
    const ids = new Set();
    for (const x of g.perf.values()) ids.add(x.id);
    for (const x of g.hc) ids.add(x.id);
    for (const x of g.ded) ids.add(x.id);
    files.set(k, { name: g.name, riders: ids.size, sheets });
  }
  return { files, latestDay, perfRowCount };
}

// مطابقة مشرف الشيت بحسابه: تطبيع كامل بس على الاسم الظاهر أو اسم المستخدم.
// لو أكتر من حساب طابق نفس الاسم → متبعتش (غموض = خطر تسريب) وبنرجّعها ambiguous.
async function repMatchUsers(env, files) {
  const rows = await env.DB.prepare("SELECT u,n,email FROM users WHERE r='sup' AND status='active'").all();
  const users = rows.results || [];
  const byN = new Map(), byU = new Map();
  for (const usr of users) {
    const kn = repNameKey(usr.n), ku = repNameKey(usr.u);
    if (kn) { if (!byN.has(kn)) byN.set(kn, []); byN.get(kn).push(usr); }
    if (ku) { if (!byU.has(ku)) byU.set(ku, []); byU.get(ku).push(usr); }
  }
  const matched = new Map(), noAccount = [], ambiguous = [];
  for (const [k, f] of files) {
    let cands = byN.get(k) || [];
    if (!cands.length) cands = byU.get(k) || [];
    if (cands.length > 1) { ambiguous.push(f.name); continue; }
    if (!cands.length) { noAccount.push(f.name); continue; }
    matched.set(k, { user: cands[0], file: f });
  }
  return { matched, noAccount, ambiguous };
}

async function runStatusCron(env) {
  await ensureSchema(env);
  // 27 Nov (24301978): Turso staging load test. While settings.notif_pause='1' the LIVE cron
  // stands down (no rider_states writes, no notifications/pushes) so staging is the single
  // notifier and live D1 keeps its write budget for logins/requests. Staging never pauses.
  // Reversible via /api/admin/notif_pause.
  if (!env.STAGING) {
    try {
      const p = await env.DB.prepare("SELECT v FROM settings WHERE k='notif_pause'").first();
      if (p && p.v === '1') {
        try {
          const entry = { ts: Date.now(), paused: 1 };
          let hist = [];
          const prevRow = await env.DB.prepare("SELECT v FROM status_meta WHERE k='cron:status_stats'").first();
          if (prevRow && prevRow.v) { const pj = JSON.parse(prevRow.v); if (Array.isArray(pj.hist)) hist = pj.hist; else if (pj.ts) hist = [pj]; }
          await env.DB.prepare("INSERT INTO status_meta(k,v) VALUES('cron:status_stats',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v")
            .bind(JSON.stringify({ ...entry, hist: [entry, ...hist].slice(0, 10) })).run();
        } catch {}
        return;
      }
    } catch {}
  }
  // 26 Nov (19219967): the live source flips between one-letter codes (W/T) and full names
  // (WORKING/TEMP_NOT_WORKING). Normalize before comparing so a format flip never fires false
  // "تغيير حالة مندوب" notifications. Every known code is the first letter of its full name.
  const STATE_NAMES = ['WORKING', 'BREAK', 'LATE', 'TEMP_NOT_WORKING', 'ENDING', 'STARTING', 'READY'];
  const normDigits = (s) => String(s || '').replace(/[\u0660-\u0669\u06F0-\u06F9]/g, (c) => String(c.charCodeAt(0) % 16));
  // "05:20:00" -> "5س 20د", "00:12:00" -> "12د"; '' for empty/zero.
  const fmtDur = (v) => {
    const m = /^(\d+):(\d{1,2})(?::(\d{1,2}))?$/.exec(String(v || '').trim());
    if (!m) return '';
    const h = +m[1], mm = +m[2];
    if (!h && !mm) return '';
    return h ? h + 'س ' + mm + 'د' : mm + 'د';
  };
  const normLiveState = (s) => {
    const t = String(s || '').trim();
    if (!t) return '';
    if (t.length === 1) { const m = STATE_NAMES.find(x => x[0] === t.toUpperCase()); if (m) return m; }
    return t.toUpperCase();
  };
  // 27 Nov staging debug: stage markers (one row, overwritten per stage) so a silently-killed
  // cron run shows where it died. Temporary - remove after the Turso load test.
  const mark = async (s) => { try { await env.DB.prepare("INSERT INTO status_meta(k,v) VALUES('cron:stage',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(JSON.stringify({ ts: Date.now(), stage: s })).run(); } catch {} };
  await mark('start');
  let res;
  try {
    const ac = new AbortController();
    const to = setTimeout(() => ac.abort('gviz_timeout'), 12000);
    res = await fetch(`https://docs.google.com/spreadsheets/d/${LIVE_SHEET_ID}/gviz/tq?tqx=out:csv&gid=${LIVE_GID}&headers=1&_=${Date.now()}`, { signal: ac.signal });
    clearTimeout(to);
  } catch (e) { await mark('fetch_threw:' + String(e).slice(0, 80)); throw e; }
  await mark('fetched:' + res.status);
  if (!res.ok) {
    // 27 Nov: make silent fetch bails visible (gviz throttling/5xx looked like "no changes").
    try { await env.DB.prepare("INSERT INTO status_meta(k,v) VALUES('cron:status_fetch_err',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(JSON.stringify({ ts: Date.now(), status: res.status })).run(); } catch {}
    return;
  }
  const rows = parseCsv(await res.text()).slice(1);
  await mark('parsed:' + rows.length);
  const current = new Map();
  for (const r of rows) {
    const id = String(r[2] || '').trim();
    if (!id || !/^[0-9A-Za-z-]{3,20}$/.test(id)) continue;
    current.set(id, {
      name: String(r[3] || '').trim().slice(0, 80),
      state: String(r[14] || '').trim().slice(0, 60),
      sup: String(r[16] || '').trim().slice(0, 80),
      zone: String(r[1] || '').trim().slice(0, 80),
      phone: String(r[4] || '').trim().slice(0, 40),
      // extra detail fields for the notification body only (27 Nov 24216213) - deliberately NOT
      // part of the change comparison or rider_states writes: they churn every minute for active
      // riders and would cost ~1.6k writes/min. gviz may render numbers with Arabic-Indic digits.
      deliveries: normDigits(String(r[7] || '').trim()).slice(0, 20),
      timeWorked: normDigits(String(r[8] || '').trim()).slice(0, 20),
      breaksTime: normDigits(String(r[12] || '').trim()).slice(0, 20),
      lateTime: normDigits(String(r[13] || '').trim()).slice(0, 20),
    });
  }
  // 26 Nov quota fix: previous state lives in a single status_meta row (1 row read)
  // instead of a full rider_states scan (~1.6k rows every 2 min = ~2M reads/day, 40% of the free D1 read limit).
  // 27 Nov (24256194): measured D1 rows written this run, from each query's meta (billing truth).
  let d1w = 0;
  let prev = null;
  try {
    const meta = await env.DB.prepare("SELECT v FROM status_meta WHERE k='prev'").first();
    if (meta && meta.v) prev = new Map(JSON.parse(meta.v));
  } catch {}
  if (!prev) {
    const prevRows = await env.DB.prepare('SELECT rider_id,name,state,sup,zone FROM rider_states').all();
    prev = new Map((prevRows.results || []).map(r => [r.rider_id, [r.state, r.name, r.sup, r.zone]]));
  }
  const seeded = prev.size > 0;
  await mark('prev:' + seeded);
  const stmts = [];
  const changedRows = []; // 27 Nov staging: collected for multi-row INSERT (see below)
  const changed = [];
  for (const [id, cur] of current) {
    const oldArr = prev.get(id);
    const old = oldArr ? { state: oldArr[0], name: oldArr[1], sup: oldArr[2], zone: oldArr[3] } : undefined;
    if (old && normLiveState(old.state) === normLiveState(cur.state) && old.name === cur.name && old.sup === cur.sup && old.zone === cur.zone) continue; // unchanged: no write
    changedRows.push([id, cur.name, cur.state, cur.sup, cur.zone, Date.now()]);
    changed.push([id, cur, old]);
  }
  // 27 Nov (Micheal 24141335): the live source drops and re-adds rows on refresh. A vanished rider
  // keeps their snapshot entry (marked gone) for GONE_GRACE_MS instead of an immediate delete, so a
  // refresh glitch no longer costs a delete+reinsert pair per rider. Back with the SAME state =
  // unchanged (no write, no notification); back with a NEW state = a real flip. The state row is
  // deleted only after the grace.
  const GONE_GRACE_MS = 30 * 60 * 1000;
  const nowTs = Date.now();
  const retainedGone = [];
  let newlyMarked = 0;
  const gone = [];
  for (const [id, arr] of prev.entries()) {
    if (current.has(id)) continue;
    const goneSince = Number(arr[4]) || nowTs;
    if (nowTs - goneSince >= GONE_GRACE_MS) {
      gone.push(env.DB.prepare('DELETE FROM rider_states WHERE rider_id=?').bind(id));
    } else {
      if (!arr[4]) newlyMarked++;
      retainedGone.push([id, [arr[0], arr[1], arr[2], arr[3], goneSince]]);
    }
  }
  if (gone.length) stmts.push(...gone);
  // 27 Nov staging (24300032): multi-row upserts, 15 riders per statement (90 params - under
  // D1's 100 bound-parameter limit), all chunks in ONE batch/pipeline call. On Turso each HTTP
  // round trip costs real latency; 350 separate upserts pushed the cron past its 30s wall-clock
  // and every detection run died silently after writing the snapshot but before stats.
  if (changedRows.length) {
    const upStmts = [];
    for (let i = 0; i < changedRows.length; i += 15) {
      const part = changedRows.slice(i, i + 15);
      const sql = 'INSERT INTO rider_states(rider_id,name,state,sup,zone,updated) VALUES ' +
        part.map(() => '(?,?,?,?,?,?)').join(',') +
        ' ON CONFLICT(rider_id) DO UPDATE SET name=excluded.name, state=excluded.state, sup=excluded.sup, zone=excluded.zone, updated=excluded.updated';
      upStmts.push(env.DB.prepare(sql).bind(...part.flat()));
    }
    try {
      const ur = await env.DB.batch(upStmts);
      for (const r of ur || []) d1w += (r && r.meta && (r.meta.rows_written || r.meta.changes)) || 0;
    } catch {}
  }
  await mark('upserted:' + changedRows.length);
  if (stmts.length) {
    const br = await env.DB.batch(stmts);
    for (const r of br || []) d1w += (r && r.meta && r.meta.rows_written) || 0;
  }
  await mark('gone_done');
  // 26 Nov quota cut: only rewrite the snapshot when something actually changed (was 1 write every 2 min).
  // Rewrite the snapshot on data changes and when vanish-marks were just added (otherwise the
  // grace clock would restart every run and rows would never age out).
  if (stmts.length || changedRows.length || newlyMarked) try {
    const snap = [];
    // 26 Nov CRITICAL: entries must be [id, [state,name,sup,zone]] - new Map() reads entry[1] as the
    // whole value. The old flat shape decoded oldArr to a STRING, so every rider looked changed every run
    // (~1,600 D1 writes every 2 min) and notifications showed old state as its first letter.
    for (const [id, cur] of current) snap.push([id, [cur.state, cur.name, cur.sup, cur.zone]]);
    for (const g of retainedGone) snap.push(g);
    const sr = await env.DB.prepare("INSERT INTO status_meta(k,v) VALUES('prev',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(JSON.stringify(snap)).run();
    d1w += (sr && sr.meta && sr.meta.rows_written) || 0;
  } catch {}
  if (!seeded) return; // first run seeds state without notifying
  // 26 Nov flood guard: >50 riders "changing state" in one 2-min run is a data-format event in the
  // source sheet, never real flips. Update state silently, send zero notifications/pushes.
  // 27 Nov fix: the flood guard now counts REAL state flips only (normalized comparison), not
  // name/sup/zone churn or raw-format flips (W<->WORKING). The old any-change guard (>50) tripped on
  // ordinary busy-hour churn and muted ALL state-change notifications, which looked broken.
  const stateChanged = [];
  for (const [id, cur, old] of changed) {
    const oldState = old ? old.state : undefined;
    if (oldState === undefined || !cur.state || normLiveState(oldState) === normLiveState(cur.state)) continue;
    stateChanged.push([id, cur, old]);
  }
  // 27 Nov (Micheal 24139285, tuned 24198928): two-level flood protection.
  // Per-supervisor: >80 flips for ONE sup in one run is a data event for that sup (he says 60 is
  // already a lot for one sup's real riders) - mute just them, everyone else still notifies.
  // Fleet-wide: >800 flips in one minute (over half the fleet) is a source glitch/reload - silent
  // run. ~600 real flips spread across supervisors notify as they should.
  const PER_SUP_CAP = 80, FLEET_GUARD = 800;
  const guard = stateChanged.length > FLEET_GUARD;
  let notified = 0, muted_sups = 0, max_per_sup = 0;
  const sendQueue = [];
  await mark('presend:' + stateChanged.length);
  if (!guard) {
    const perSup = new Map();   // target user -> [[id, cur, old], ...]
    // 27 Nov staging (24300032): load active users ONCE (1 DB round trip) and match in JS.
    // The old sequential per-sup queries each cost a full Turso HTTP round trip (~1s) and
    // pushed every flip-heavy cron run past the 30s wall-clock - silent death before stats.
    let allUsers = [];
    try { const ur = await env.DB.prepare("SELECT u, n FROM users WHERE status='active'").all(); allUsers = ur.results || []; } catch {}
    const resolveSup = (supName) => {
      const lower = String(supName || '').toLowerCase();
      let hits = allUsers.filter(x => x.n === supName || x.u === lower).map(x => x.u);
      if (!hits.length && supName) { const needle = supName.replace(/%/g, ''); hits = allUsers.filter(x => String(x.n || '').includes(needle)).map(x => x.u); }
      return [...new Set(hits)];
    };
    for (const [id, cur, old] of stateChanged) {
      const targetList = cur.sup ? resolveSup(cur.sup) : [];
      for (const u of targetList) {
        if (!perSup.has(u)) perSup.set(u, []);
        perSup.get(u).push([id, cur, old]);
      }
    }
    for (const [u, flips] of perSup) {
      if (flips.length > max_per_sup) max_per_sup = flips.length;
      if (flips.length > PER_SUP_CAP) { muted_sups++; continue; } // that sup only; others notify
      for (const [id, cur, old] of flips) {
        const oldState = old ? old.state : undefined;
        // 27 Nov (Micheal 24163340/24172059): ID first line, name under it, then the status
        // change, phone, zone, and the supervisor's name. Emoji + Android icon color per new state.
        const sm = STATE_STYLE[normLiveState(cur.state)] || STATE_STYLE._;
        const fromStyle = oldState ? (STATE_STYLE[normLiveState(oldState)] || STATE_STYLE._) : null;
        const transition = 'من ' + (fromStyle ? fromStyle[0] + ' ' : '') + (oldState ? normLiveState(oldState) : 'بدون حالة') + ' إلى ' + sm[0] + ' ' + normLiveState(cur.state);
        const lines = [id, cur.name || 'مندوب', transition];
        if (cur.phone) lines.push('📞 ' + cur.phone);
        if (cur.zone) lines.push('الزون: ' + cur.zone);
        if (cur.sup) lines.push('المشرف: ' + cur.sup);
        // 27 Nov (24216213 + 24217141): live stats from the sheet, each on its OWN line so the
        // expanded push reads clearly; empty fields skipped (STARTING has no timer).
        const tw = fmtDur(cur.timeWorked); if (tw) lines.push('⏱ شغال: ' + tw);
        const bt = fmtDur(cur.breaksTime); if (bt) lines.push('☕ بريك: ' + bt);
        if (cur.deliveries && cur.deliveries !== '0') lines.push('📦 الأوردرات: ' + cur.deliveries);
        const lt = fmtDur(cur.lateTime); if (lt) lines.push('⏰ تأخير: ' + lt);
        sendQueue.push([u, sm[0] + ' تغيير حالة مندوب', lines.join('\n'), id, sm[1]]);
      }
    }
  }
  // 27 Nov: per-state histogram of what the cron ACTUALLY read - distinguishes a stale gviz read
  // from a comparison bug when flips seem missed.
  const stateCounts = {};
  for (const [, cur] of current) { const k = normLiveState(cur.state) || 'EMPTY'; stateCounts[k] = (stateCounts[k] || 0) + 1; }
  notified = sendQueue.length;
  await mark('queue:' + sendQueue.length + ':' + muted_sups);
  // 27 Nov: per-run stats for the admin usage page (1 write/min) so notification health is visible.
  // hist keeps the last 9 runs: a single overwrite hid detection runs that were followed by a quiet run.
  // Stats are written BEFORE the send loop: even if a huge batch overruns the cron wall-clock
  // mid-send, the detection (and how many were queued) is always recorded.
  try {
    const entry = { ts: Date.now(), riders: current.size, changed_any: changed.length, changed_state: stateChanged.length, notified, guard, muted_sups, max_per_sup, states: stateCounts, d1w_pre: d1w };
    let hist = [];
    try {
      const prevRow = await env.DB.prepare("SELECT v FROM status_meta WHERE k='cron:status_stats'").first();
      if (prevRow && prevRow.v) { const p = JSON.parse(prevRow.v); if (Array.isArray(p.hist)) hist = p.hist; else if (p.ts) hist = [p]; }
    } catch {}
    const stw = await env.DB.prepare("INSERT INTO status_meta(k,v) VALUES('cron:status_stats',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v")
      .bind(JSON.stringify({ ...entry, hist: [entry, ...hist].slice(0, 10) })).run();
    d1w += (stw && stw.meta && stw.meta.rows_written) || 0;
  } catch {}
  // Sends run AFTER stats are saved, in parallel chunks so a ~600-flip minute stays inside the
  // cron limit (sequential awaits overran it and the run died before stats - pushes went out but
  // the run looked like a zero).
  // 27 Nov staging (24300032): batch the notification ROWS as multi-row INSERTs (15 rows per
  // statement - D1's 100 bound-parameter limit), all chunks in ONE batch/pipeline call per 300.
  // One insertNotification round trip per flip overran the cron wall-clock on Turso latency.
  // Same rows, same pushes; identical semantics on D1 after the live cron resumes.
  const dayNow = cairoDay();
  for (let i = 0; i < sendQueue.length; i += 300) {
    const part = sendQueue.slice(i, i + 300);
    try {
      const nStmts = [];
      for (let j = 0; j < part.length; j += 15) {
        const rows = part.slice(j, j + 15);
        const sql = 'INSERT INTO notifications(u,day,title,body,rider_id,ts) VALUES ' + rows.map(() => '(?,?,?,?,?,?)').join(',');
        const args = [];
        for (const [u, title, body, id] of rows) args.push(u, dayNow, String(title || '').slice(0, 120), String(body || '').slice(0, 500), String(id || '').slice(0, 40), Date.now());
        nStmts.push(env.DB.prepare(sql).bind(...args));
      }
      const ress = await env.DB.batch(nStmts);
      for (const r of ress || []) d1w += (r && r.meta && r.meta.rows_written) || 0;
    } catch {}
  }
  // Pushes after the rows: pre-scan tokens once (1 query) and FCM only users that have any.
  try {
    const uniqU = [...new Set(sendQueue.map(([u]) => u))];
    if (uniqU.length) {
      const tokRows = await env.DB.prepare(`SELECT u, token FROM push_tokens WHERE u IN (${uniqU.map(() => '?').join(',')})`).bind(...uniqU).all();
      const hasTok = new Set((tokRows.results || []).map(r => r.u));
      const withPush = sendQueue.filter(([u]) => hasTok.has(u));
      const CHUNK = 10;
      for (let i = 0; i < withPush.length; i += CHUNK) {
        await Promise.all(withPush.slice(i, i + CHUNK).map(([u, title, body, id, color]) => sendFcmToUser(env, u, String(title || '').slice(0, 120), String(body || '').slice(0, 500), id, color).catch(() => 0)));
      }
    }
  } catch {}
  // Patch the stats entry with the FULL measured write total (states + snapshot + stats + notification rows).
  try {
    const row = await env.DB.prepare("SELECT v FROM status_meta WHERE k='cron:status_stats'").first();
    if (row && row.v) {
      const p = JSON.parse(row.v);
      if (Array.isArray(p.hist) && p.hist.length) { p.hist[0].d1w = d1w; p.d1w = d1w; await env.DB.prepare("UPDATE status_meta SET v=? WHERE k='cron:status_stats'").bind(JSON.stringify(p)).run(); }
    }
  } catch {}
}

// 26 Nov (19271108 upgrade 4): morning summary push to admins at 09:00 Cairo (cron 0 7 * * * UTC).
// Idempotent per Cairo day via status_meta so a duplicate cron fire (or both workers) sends it once.
async function runMorningSummary(env, force) {
  await ensureSchema(env);
  const day = cairoDay();
  if (!force) {
    const mark = await env.DB.prepare("INSERT OR IGNORE INTO status_meta(k,v) VALUES(?,?)").bind('morning:' + day, String(Date.now())).run();
    if (!(mark.meta && mark.meta.changes)) return { sent: 0, skipped: true };
  }
  const rows = await env.DB.prepare('SELECT state, COUNT(*) AS c FROM rider_states GROUP BY state').all();
  const counts = {};
  let total = 0;
  for (const r of (rows.results || [])) { const k = String(r.state || '').toUpperCase() || 'UNKNOWN'; counts[k] = r.c; total += r.c; }
  const statsText = 'التاريخ: ' + day + '\nإجمالي الطيارين المتتبعين: ' + total + '\n' +
    Object.entries(counts).map(([k, v]) => k + ': ' + v).join('\n');
  let summary = '';
  if (env.AI) {
    try {
      const r = await env.AI.run('@cf/meta/llama-3.3-70b-instruct-fp8-fast', {
        messages: [
          { role: 'system', content: 'إنت مساعد Team MH. اكتب ملخص صباحي بالعامية المصرية لمدير التشغيل عن حالة الطيارين دلوقتي، في 4 سطور قصيرة كحد أقصى. استخدم الأرقام زي ما هي بالظبط من غير ما تخترع حاجة. ابدأ بتحية قصيرة زي "صباح الخير يا معلم".' },
          { role: 'user', content: statsText },
        ],
        max_tokens: 300,
      });
      summary = String((r && r.response) || '').trim();
    } catch {}
  }
  if (!summary) summary = 'صباح الخير ☀️\nالطيارين دلوقتي: ' + total + '\n' + Object.entries(counts).map(([k, v]) => k + ': ' + v).join('، ');
  summary = summary.slice(0, 480);
  const admins = await env.DB.prepare("SELECT u FROM users WHERE status='active' AND r='admin'").all();
  let sent = 0;
  for (const a of (admins.results || [])) { await insertNotification(env, a.u, '☀️ ملخص الصباح', summary, ''); sent++; }
  return { sent, preview: summary };
}

// ---- Scheduled shift commands (26 Nov) ----
function cairoNowParts() {
  const parts = new Intl.DateTimeFormat('en-US', { timeZone: 'Africa/Cairo', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).formatToParts(new Date());
  const g = (t) => (parts.find(p => p.type === t) || {}).value || '';
  return { day: g('year') + '-' + g('month') + '-' + g('day'), hm: g('hour') + ':' + g('minute') };
}
// Same normalization the site applies (extNormZone): sheet zone label -> form city value.
function normZoneCity(z) {
  const zl = String(z || '').trim().toLowerCase();
  const m = { 'alexandria': 'الإسكندرية', 'alex': 'الإسكندرية', 'ismalia city': 'الإسماعيلية', 'ismailia city': 'الإسماعيلية', 'mansoura': 'المنصورة', 'minya': 'المنيا', 'tanta': 'طنطا', 'zagazig': 'الزقازيق', 'hurghada': 'الغردقة', 'hurgada': 'الغردقة', 'الغردقه': 'الغردقة', 'suez': 'السويس', 'ismailia': 'الإسماعيلية', 'الاسماعيليه': 'الإسماعيلية' };
  return m[zl] || String(z || '').trim();
}
async function runScheduleCron(env) {
  await ensureSchema(env);
  const { day, hm } = cairoNowParts();
  const rows = await env.DB.prepare('SELECT * FROM shiftcmd_schedules WHERE enabled=1').all();
  const now = Date.now();
  for (const s of (rows.results || [])) {
    try {
      if (s.last_run === day) continue; // already fired today
      if (String(s.time_hhmm) > hm) continue; // not due yet (string compare works on HH:MM)
      let targets = [];
      if (s.target === 'break_all') {
        const br = await env.DB.prepare("SELECT rider_id,zone FROM rider_states WHERE state='BREAK'").all();
        targets = (br.results || []).map(r => ({ rider_id: r.rider_id, city: normZoneCity(r.zone) || s.city }));
      } else {
        targets = String(s.codes).split(/[^0-9]+/).filter(Boolean).slice(0, 50).map(id => ({ rider_id: id, city: s.city }));
      }
      let n = 0, skipped = 0;
      for (const t of targets) {
        if (!t.rider_id || !t.city) { skipped++; continue; }
        if (s.action === 'break' && t.city === 'الإسكندرية' && !s.reason) { skipped++; continue; }
        const payload = { action: s.action, rider_id: t.rider_id, city: t.city, duration24: s.duration24 || '', reason: s.reason || '', vehicle: s.vehicle || '' };
        const dup = await env.DB.prepare("SELECT id FROM shift_commands WHERE status IN ('pending','claimed') AND payload LIKE ? AND payload LIKE ? LIMIT 1")
          .bind('%"action":"' + s.action + '"%', '%"rider_id":"' + t.rider_id + '"%').first();
        if (dup) { skipped++; continue; }
        await env.DB.prepare("INSERT INTO shift_commands(u,payload,status,ts,updated) VALUES(?,?,'pending',?,?)").bind(s.by_u, JSON.stringify(payload), now, now).run();
        n++;
      }
      await env.DB.prepare('UPDATE shiftcmd_schedules SET last_run=? WHERE id=?').bind(day, s.id).run();
      if (!s.daily) await env.DB.prepare('UPDATE shiftcmd_schedules SET enabled=0 WHERE id=?').bind(s.id).run();
      const actL = s.action === 'extend' ? 'مد الشيفت' : s.action === 'break' ? 'فك البريك' : 'فتح شيفت';
      const admins = await env.DB.prepare("SELECT u FROM users WHERE r='admin' AND status='active'").all();
      for (const a of (admins.results || [])) {
        await insertNotification(env, a.u, '⏰ أمر مجدول اتنفذ', actL + (s.target === 'break_all' ? ' لكل اللي على البريك' : '') + ' الساعة ' + s.time_hhmm + ': ' + n + ' أمر اتضاف للطابور' + (skipped ? ' (' + skipped + ' اتخطّى)' : ''), '');
      }
    } catch (e) { /* one bad schedule never blocks the rest */ }
  }
}

// 26 Nov: stopped-rider watchdog (Micheal 18742196). Every 2 min, compare the live map snapshot
// positions with the last known spot; a rider holding an order who has not moved ~40m for 30+
// minutes pushes one alert to the admins. Clock only ticks while the rider has an order and is
// not on break; moving, going offline, or finishing the order resets the episode.
const STOPPED_RIDER_MS = 30 * 60 * 1000;
const STOPPED_RIDER_MOVED_DEG = 0.0004; // ~40m
async function runStoppedRiderCron(env) {
  await ensureSchema(env);
  if (await isMapPaused(env)) return; // map paused by admin (quota saver)
  const hub = env.RIDER_MAP_HUB.get(env.RIDER_MAP_HUB.idFromName('riders-global'));
  const resp = await hub.fetch('https://rider-map.internal/snapshot');
  if (!resp.ok) return;
  const snap = await resp.json().catch(() => null);
  const riders = snap && Array.isArray(snap.riders) ? snap.riders : [];
  const now = Date.now();
  for (const r of riders) {
    try {
      const id = String(r.id || '').trim();
      const lat = Number(r.latitude), lng = Number(r.longitude);
      if (!id || !Number.isFinite(lat) || !Number.isFinite(lng)) continue;
      const orders = Number.isFinite(Number(r.ongoing_orders)) ? Number(r.ongoing_orders)
        : (Array.isArray(r.active_orders) ? r.active_orders.length : (Array.isArray(r.active_delivery_ids) ? r.active_delivery_ids.length : 0));
      const onBreak = /break|بريك/i.test(String(r.state || ''));
      const prev = await env.DB.prepare('SELECT lat,lng,since,alerted FROM rider_stops WHERE rider_id=?').bind(id).first();
      const moved = !prev || Math.abs(Number(prev.lat) - lat) > STOPPED_RIDER_MOVED_DEG || Math.abs(Number(prev.lng) - lng) > STOPPED_RIDER_MOVED_DEG;
      if (moved || orders <= 0 || onBreak) {
        // reposition / idle: (re)start the clock, clear any fired alert
        await env.DB.prepare('INSERT INTO rider_stops(rider_id,lat,lng,since,alerted,seen_at) VALUES(?,?,?,?,0,?) ON CONFLICT(rider_id) DO UPDATE SET lat=excluded.lat,lng=excluded.lng,since=excluded.since,alerted=0,seen_at=excluded.seen_at')
          .bind(id, lat, lng, now, now).run();
        continue;
      }
      await env.DB.prepare('UPDATE rider_stops SET seen_at=? WHERE rider_id=?').bind(now, id).run();
      if (prev.alerted || now - Number(prev.since) < STOPPED_RIDER_MS) continue;
      await env.DB.prepare('UPDATE rider_stops SET alerted=1 WHERE rider_id=?').bind(id).run();
      const mins = Math.round((now - Number(prev.since)) / 60000);
      const name = String(r.name || id).slice(0, 60);
      const admins = await env.DB.prepare("SELECT u FROM users WHERE r='admin' AND status='active'").all();
      for (const a of (admins.results || [])) {
        await insertNotification(env, a.u, '🛑 طيار واقف مكانه', name + ' (' + id + ') واقف مكانه من ' + mins + ' دقيقة ومعاه ' + orders + ' أوردر', id);
      }
    } catch (e) { /* one bad rider never blocks the rest */ }
  }
  // drop trackers for riders who went offline (next appearance restarts the clock)
  if (riders.length) {
    await env.DB.prepare('DELETE FROM rider_stops WHERE seen_at<?').bind(now - 15 * 60 * 1000).run();
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
  async fetch(request, rawEnv, ctx) {
    // 27 Nov staging debug: surface uncaught errors as text instead of a bare 1101 page.
    try { return await handleFetch(request, rawEnv, ctx); }
    catch (e) { return new Response('WORKER_ERR ' + String((e && e.stack) || e).slice(0, 500), { status: 500 }); }
  },
  async scheduled(event, rawEnv, ctx) {
    // same wrapper for cron: log the failure into status_meta so /api/admin/usage shows it.
    try { return await handleScheduled(event, rawEnv, ctx); }
    catch (e) {
      try {
        const env = withDb(rawEnv);
        await env.DB.prepare("INSERT INTO status_meta(k,v) VALUES('cron:status_fetch_err',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(JSON.stringify({ ts: Date.now(), crash: String(e).slice(0, 300) })).run();
      } catch {}
      throw e;
    }
  }
};
async function handleFetch(request, rawEnv, ctx) {
    const env = withDb(rawEnv);
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
    // 25 Nov: docs.google.com added to script-src - the supervisor-login audit panel loads its gviz JSONP <script> from there (was CSP-blocked on mobile/desktop, showing فشل الاتصال بجدول البيانات).
    const CSP = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com https://docs.google.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob: https:; connect-src 'self' https: wss:; media-src 'self' data: blob:; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
    const withSec = (resp, isHtml) => {
      const h = new Headers(resp.headers);
      for (const [k, v] of Object.entries(SEC_HEADERS)) h.set(k, v);
      if (isHtml) {
        h.set('Content-Security-Policy', CSP); h.set('Cache-Control', 'no-store');
        // 25 Nov: chat voice notes need mic access on the dashboard page (recording is opt-in per note).
        h.set('Permissions-Policy', 'camera=(), microphone=(self), payment=()');
      }
      return new Response(resp.body, { status: resp.status, headers: h });
    };
    const hub = env.RIDER_MAP_HUB.get(env.RIDER_MAP_HUB.idFromName('riders-global'));

    // 25 Nov: desktop download hosted here (replaces public GitHub release links before repo goes private).
    // The 126MB zip is chunked in /dl-chunks/ (assets limit 25MiB/file). Worker-side streaming hit the
    // free CPU cap mid-stream, so this page merges the chunks in the browser (plain cached 20MB GETs).
    if (url.pathname === '/dl/desktop' && request.method === 'GET') {
      const page = '<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TEAM MH | تحميل نسخة الكمبيوتر</title>'
        + '<style>body{margin:0;background:#101827;color:#edf2fa;font:17px system-ui;display:grid;place-items:center;min-height:100vh}main{max-width:430px;padding:24px;text-align:center}button{background:#2dc19f;color:#06231b;border:0;border-radius:10px;padding:14px 28px;font:inherit;font-weight:700;cursor:pointer}#bar{height:12px;border-radius:99px;background:#1b293e;overflow:hidden;margin:16px 0 6px}#fill{height:100%;width:0%;background:#2dc19f;transition:width .3s}.sub{color:#8fa1b8;font-size:14px}</style>'
        + '<main><h1>تحميل نسخة الكمبيوتر TEAM MH</h1><p class="sub">اضغط الزر واستنى شوية — هينزل ملف تثبيت واحد (82 ميجا). شغّله وهيثبّت البرنامج لوحده ويحط أيقونة على سطح المكتب. من النسخة دي التحديثات بتوصل لوحدها من غير ما تحمّل حاجة تاني، والبرنامج بيفضل شغال جنب الساعة حتى لو قفلت الشباك (الخروج الكامل من كليك يمين على الأيقونة جنب الساعة ← إنهاء).</p><button id="go">⬇️ تحميل team_mh Setup</button><div id="bar" hidden><div id="fill"></div></div><p class="sub" id="st"></p></main>'
        + '<script>const chunks=["desktop40-00.bin","desktop40-01.bin","desktop40-02.bin","desktop40-03.bin","desktop40-04.bin","desktop40-05.bin","desktop40-06.bin"];'
        + 'document.getElementById("go").onclick=async()=>{const st=document.getElementById("st"),fill=document.getElementById("fill");document.getElementById("bar").hidden=false;'
        + 'try{const parts=[];let done=0;for(const c of chunks){st.textContent="بيتحمّل... "+Math.round(done/chunks.length*100)+"%";const r=await fetch("/dl-chunks/"+c,{cache:"default"});if(!r.ok)throw new Error("fetch failed: "+r.status);parts.push(await r.arrayBuffer());done++;fill.style.width=(done/chunks.length*100)+"%"}'
        + 'st.textContent="بيحفظ الملف...";const blob=new Blob(parts,{type:"application/octet-stream"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="team_mh-Setup-0.4.0.exe";a.click();'
        + 'st.textContent="✅ نزل ملف التثبيت ("+(blob.size/1048576).toFixed(0)+" ميجا) — شغّله وهو هيكمّل لوحده. لو ويندوز أظهر رسالة حماية زرقاء اضغط معلومات إضافية ثم تشغيل على أي حال"}catch(e){st.textContent="❌ حصلت مشكلة في التحميل — جرب تاني"} };</script>';
      const h = new Headers({ ...SEC_HEADERS, 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      h.set('Content-Security-Policy', "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'");
      return new Response(page, { headers: h });
    }

    // convenience: the current APK already lives at /app.apk
    if (url.pathname === '/dl/apk' && request.method === 'GET') {
      return Response.redirect(new URL('/app.apk', url).toString(), 302);
    }

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

    // 25 Nov (Micheal 16288124): the legal role is fenced into شئون قانونية — every other
    // data API 403s for it. The client hides everything else and lands it on the legal tab.
    if (url.pathname.startsWith('/api/') && !url.pathname.startsWith('/api/auth/') && !url.pathname.startsWith('/api/legal/')) {
      try {
        const u0 = await getSessionUser(env, request);
        if (u0 && u0.r === 'legal') return json({ error: 'forbidden' }, 403);
      } catch (e) { return serverErr(e); }
    }

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

    if (url.pathname === '/api/sheet/csv') {
      try {
        const handled = await handleSheetProxy(request, env, json, url, ctx);
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

    if (url.pathname.startsWith('/api/legal/')) {
      try {
        await ensureSchema(env);
        const handled = await handleLegal(request, env, json, url);
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
            // remember which default-hidden tabs the admin explicitly opened, so they stay open
            const shown = DEFAULT_HIDDEN_TABS.filter(t => !list.includes(t));
            await env.DB.prepare("INSERT INTO settings(k,v) VALUES('shown_tabs',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(JSON.stringify(shown)).run();
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

    // 26 Nov: let a signed-in user check their own registered FCM devices (test-push diagnostics).
    if (url.pathname === '/api/push/status' && request.method === 'GET') {
      try {
        await ensureSchema(env);
        const user = await getSessionUser(env, request);
        if (!user) return json({ error: 'unauthorized' }, 401);
        const rows = await env.DB.prepare('SELECT token,ts FROM push_tokens WHERE u=? ORDER BY ts DESC').bind(user.u).all();
        const list = rows.results || [];
        const logs = await env.DB.prepare('SELECT token_tail,status,resp,ts FROM push_log WHERE u=? ORDER BY ts DESC LIMIT 5').bind(user.u).all().catch(() => ({ results: [] }));
        return json({ registered: list.length > 0, devices: list.length, last_ts: list.length ? list[0].ts : 0, fcm_configured: !!env.FCM_SA_JSON, fcm_project: env.FCM_PROJECT_ID || 'pilot-dashboard-d0983', last_sends: logs.results || [] });
      } catch (e) { return serverErr(e); }
    }

    // تقارير المشرفين (Micheal 25 Nov): أدمن بس — يبعت Excel لكل مشرف على إيميله
    // فيه مناديبه بس (التقييد سيرفر-سايد)، أو يحمّل معاينة لملف مشرف واحد من غير إرسال.
    if ((url.pathname === '/api/reports/send' || url.pathname === '/api/reports/preview') && request.method === 'POST') {
      try {
        await ensureSchema(env);
        const user = await getSessionUser(env, request);
        if (!user) return json({ error: 'unauthorized' }, 401);
        if (user.r !== 'admin') return json({ error: 'forbidden' }, 403);
        const body = await request.json().catch(() => null);
        const types = Array.isArray(body && body.types) ? body.types.filter(t => REPORT_TYPES[t]) : [];
        // يوم واحد (day) أو فترة (d1 إلى d2) — الفترة بتأثر على تقرير الأداء بس؛ المحافظ/العقود حالة حالية لحد d2
        let d1 = String(body && (body.d1 || body.day) || '').trim();
        let d2 = String(body && (body.d2 || body.day) || '').trim();
        if (!types.length) return json({ error: 'no_types' }, 400);
        // الفترة للأداء بس — المحافظ/العقود حالة حالية ومش مرتبطة بتاريخ (توضيح Micheal 25 Nov)
        if (types.includes('perf')) {
          const okDay = d => /^\d{4}-\d{2}-\d{2}$/.test(d) && d <= cairoDay() && d >= '2024-01-01';
          if (!okDay(d1) || !okDay(d2)) return json({ error: 'bad_day' }, 400);
          if (d1 > d2) { const t = d1; d1 = d2; d2 = t; }
          if ((Date.parse(d2) - Date.parse(d1)) / 86400000 > 62) return json({ error: 'range_too_long' }, 400);
        } else { d1 = d2 = cairoDay(); }
        const dayLabel = types.includes('perf') ? (d1 === d2 ? d1 : (d1 + ' إلى ' + d2)) : cairoDay();
        const isPreview = url.pathname === '/api/reports/preview';
        if (!isPreview) {
          const dayKey = cairoDay() + ':' + user.u;
          const used = _repUse.get(dayKey) || 0;
          if (used >= 20) return json({ error: 'daily_limit', wait: 3600 }, 429);
          _repUse.set(dayKey, used + 1);
          if (_repUse.size > 500) { for (const k of _repUse.keys()) if (!k.startsWith(cairoDay())) _repUse.delete(k); }
        }
        const assembled = await repAssemble(env, types, d1, d2);
        const files = assembled.files;
        const attName = 'team_mh_report_' + (d1 === d2 ? d1 : d1 + '_to_' + d2) + '.xlsx';
        if (isPreview) {
          const supName = repNameKey(body && body.sup);
          const f = files.get(supName);
          if (!f) return json({ error: 'sup_not_found' }, 404);
          const bytes = repBuildXlsx(f.sheets);
          return new Response(bytes, { headers: {
            'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'Content-Disposition': 'attachment; filename="' + attName + '"',
          } });
        }
        const { matched, noAccount, ambiguous } = await repMatchUsers(env, files);
        // اختياري: الإرسال لمشرف أو أكتر بأسمائهم (body.sups أو body.sup باسم المشرف زي الشيت)
        const onlySet = new Set();
        if (body && body.sup) onlySet.add(repNameKey(body.sup));
        if (body && Array.isArray(body.sups)) for (const nm of body.sups) onlySet.add(repNameKey(nm));
        const onlyKey = onlySet.size === 1 ? [...onlySet][0] : '';
        const sent = [], failed = [], ready = [], noEmail = [];
        // Micheal 25 Nov: "ready" = matched AND has a real registered email on the site account.
        // Matched accounts without an email go ONLY to noEmail - never counted as ready,
        // and the send loop below skips them, so no report can go to a wrong/guessed address.
        for (const m of matched.values()) {
          const em = String(m.user.email || '').trim();
          if (em) ready.push({ sup: m.file.name, u: m.user.u, email: em, riders: m.file.riders });
          else noEmail.push({ sup: m.file.name, u: m.user.u });
        }
        if (!body.dryRun) {
          for (const [mk, m] of matched) {
            if (onlySet.size && !onlySet.has(mk)) continue;
            const email = String(m.user.email || '').trim();
            if (!email) continue;
            const bytes = repBuildXlsx(m.file.sheets);
            const sections = types.map(t => '• ' + REPORT_TYPES[t]).join('\n');
            const text = 'أهلًا ' + m.user.n + ' 👋\n\nده تقرير TEAM MH عن ' + (d1 === d2 ? 'يوم ' + d1 : 'الفترة من ' + d1 + ' إلى ' + d2) + ' — البيانات اللي فيه خاصة بمناديبك بس.\n\nالأقسام الموجودة في ملف الإكسل المرفق:\n' + sections + '\n\nالتقرير اتولّد أوتوماتيك من لوحة المتابعة. لو فيه رقم مش مظبوط كلم الإدارة.';
            const mail = await sendMail(env, email, 'تقرير TEAM MH — ' + dayLabel, text, { name: attName, content: repU8ToB64(bytes) });
            if (mail.ok) sent.push({ sup: m.file.name, u: m.user.u, email, riders: m.file.riders });
            else failed.push({ sup: m.file.name, u: m.user.u, email, error: mail.error || ('HTTP ' + mail.status) });
          }
          try {
            await env.DB.prepare('INSERT INTO report_logs(admin_u,day,types,sent,failed,ts) VALUES(?,?,?,?,?,?)')
              .bind(user.u, dayLabel, types.join(','), sent.length, failed.length, Date.now()).run();
          } catch (e) {}
        }
        return json({
          ok: true, day: d2, d1, d2, types, dryRun: !!body.dryRun, latestDay: assembled.latestDay, only: onlyKey || undefined, perfRows: assembled.perfRowCount,
          ready,
          sent, failed, noEmail, noAccount, ambiguous,
          supCount: files.size,
        });
      } catch (e) {
        if (String(e && e.message) === 'sheet_fetch_failed') return json({ error: 'sheet_fetch_failed' }, 502);
        return serverErr(e);
      }
    }

    if (url.pathname === '/api/assistant' && request.method === 'POST') {
      try {
        const user = await getSessionUser(env, request);
        if (!user) return json({ error: 'unauthorized' }, 401);
        if (!['admin', 'manager', 'sup'].includes(user.r)) return json({ error: 'forbidden' }, 403);
        if (!env.AI) return json({ error: 'ai_unavailable' }, 503);
        await ensureSchema(env);
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
        const sys = 'إنت "TEAM MH"، مساعد لوحة تحكم Team MH لمتابعة أداء المناديب (الطيارين). بتجاوب دايمًا بالعامية المصرية، باختصار ووضوح. بتشوف أسئلة المستخدم السابقة وردودك عليها في المحادثة، فلو سأل سؤال مكمل أو رجع لموضوع قديم، استخدم السياق ده. مهم: لو السؤال مكمل لموضوع سابق مش محتاج بيانات اللوحة (زي معادلة أو ترجمة أو شرح)، كمّل عادي من سياق المحادثة حتى لو بيانات اللوحة فاضية، ومتقولش "مفيش بيانات". أنواع الأسئلة: (1) سؤال عن بيانات اللوحة: جاوب من البيانات المبعوتة في رسالة المستخدم بس، متخترعش أرقام، ولو البيانات مش كفاية قول ده بصراحة. (2) طلب ترجمة: لو طلب ترجمة من العربي للإنجليزي أو العكس، ترجم النص بدقة وبس من غير زيادات، وحافظ على الأرقام والأسماء، ولو النص شغل (طلبات/شيفتات/مناديب) فهمّه المصطلحات صح. (3) سؤال عن معادلات Excel أو Google Sheets: افهم المعادلة واشرحها بالعربي خطوة خطوة، أو اكتبله المعادلة اللي يحتاجها بصيغة صحيحة شغالة في الاتنين، مع مثال قصير. (4) سؤال عام مش له علاقة بالبيانات: جاوب عادي من معرفتك وساعده برضه، وخلّي إجابتك قصيرة ومفيدة، ومتقولش إن ده من بيانات اللوحة. نسّق الإجابة في سطور قصيرة، ولو فيها قائمة خلي كل بند في سطر.';
        // 26 Nov (19271108 upgrade 2): remember each user's past Q&A in D1 and feed the last 6
        // exchanges into the prompt so follow-up questions have context.
        const histRows = await env.DB.prepare('SELECT q,a FROM assistant_history WHERE u=? ORDER BY ts DESC LIMIT 6').bind(user.u).all().catch(() => null);
        const hist = ((histRows && histRows.results) || []).reverse();
        const msgs = [{ role: 'system', content: sys }];
        for (const h of hist) {
          msgs.push({ role: 'user', content: String(h.q || '').slice(0, 300) });
          msgs.push({ role: 'assistant', content: String(h.a || '').slice(0, 500) });
        }
        msgs.push({ role: 'user', content: 'بيانات اللوحة الحالية (JSON):\n' + ctxStr + '\n\nالسؤال: ' + q });
        const r = await env.AI.run('@cf/meta/llama-3.3-70b-instruct-fp8-fast', { messages: msgs, max_tokens: 600 });
        const ans = String((r && r.response) || '').trim() || 'معنديش إجابة واضحة من البيانات الحالية.';
        try {
          await env.DB.prepare('INSERT INTO assistant_history(u,ts,q,a) VALUES(?,?,?,?)').bind(user.u, Date.now(), q.slice(0, 600), ans.slice(0, 800)).run();
          await env.DB.prepare('DELETE FROM assistant_history WHERE u=? AND ts < COALESCE((SELECT MIN(ts) FROM (SELECT ts FROM assistant_history WHERE u=? ORDER BY ts DESC LIMIT 30)),0)').bind(user.u, user.u).run();
        } catch {}
        return json({ ok: true, answer: ans, history: hist.length });
      } catch (e) { return serverErr(e); }
    }

    // 26 Nov (19271108 upgrade 4): admin-only manual trigger for the morning summary (also used to verify it end-to-end).
    if (url.pathname === '/api/assistant/morning-summary' && request.method === 'POST') {
      try {
        await ensureSchema(env);
        const user = await getSessionUser(env, request);
        if (!user) return json({ error: 'unauthorized' }, 401);
        if (user.r !== 'admin') return json({ error: 'forbidden' }, 403);
        const out = await runMorningSummary(env, true);
        return json({ ok: true, sent: out.sent, preview: out.preview });
      } catch (e) { return serverErr(e); }
    }

    if (url.pathname === '/api/notifications' || url.pathname === '/api/notifications/read' || url.pathname === '/api/notifications/purge-state-flips' || url.pathname === '/api/notifications/clear-all' || url.pathname === '/api/notifications/clear-mine' || url.pathname === '/api/notifications/test') {
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
          const cu = await env.DB.prepare('SELECT COUNT(*) AS c FROM chat_messages WHERE to_u=? AND read_at IS NULL').bind(user.u).first().catch(() => null);
          return json({ day, count: items.length, unread: items.filter(i => i.ts > readTs).length, chat_unread: (cu && cu.c) || 0, items });
        }
        if (url.pathname === '/api/notifications/read' && request.method === 'POST') {
          await env.DB.prepare('INSERT INTO notifications_read(u,ts) VALUES(?,?) ON CONFLICT(u) DO UPDATE SET ts=excluded.ts').bind(user.u, Date.now()).run();
          return json({ ok: true });
        }
        // 26 Nov (Micheal 19222604): purge false "state flip" notifications — rows whose OLD state
        // is a single-letter code (من "W" إلى "WORKING") fired when the live source flipped format.
        if (url.pathname === '/api/notifications/purge-state-flips' && request.method === 'POST') {
          if (user.r !== 'admin') return json({ error: 'forbidden' }, 403);
          const r = await env.DB.prepare(`DELETE FROM notifications WHERE title='تغيير حالة مندوب' AND day=? AND body LIKE '%من "_" إلى "%"'`).bind(cairoDay()).run();
          return json({ ok: true, deleted: (r.meta && r.meta.changes) || 0 });
        }
        // 26 Nov (Micheal 19282208): admin-only "clear notifications for everyone" button.
        if (url.pathname === '/api/notifications/clear-all' && request.method === 'POST') {
          if (user.r !== 'admin') return json({ error: 'forbidden' }, 403);
          const r = await env.DB.prepare('DELETE FROM notifications').run();
          return json({ ok: true, deleted: (r.meta && r.meta.changes) || 0 });
        }
        // 27 Nov (Micheal 24177597): any user clears ALL their own notification rows at once
        // (scoped strictly to the session user; also frees D1 space).
        if (url.pathname === '/api/notifications/clear-mine' && request.method === 'POST') {
          const r = await env.DB.prepare('DELETE FROM notifications WHERE u=?').bind(user.u).run();
          return json({ ok: true, deleted: (r.meta && r.meta.changes) || 0 });
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

    // Micheal 26 Nov (19157868): admin pause switch for the live map to save the daily quota
    if (url.pathname === '/api/rider-map/pause' && request.method === 'POST') {
      try {
        await ensureSchema(env);
        const user = await getSessionUser(env, request);
        if (!user) return json({ error: 'unauthorized' }, 401);
        if (user.r !== 'admin') return json({ error: 'forbidden' }, 403);
        const body = await request.json().catch(() => ({}));
        const paused = !!(body && body.paused);
        await env.DB.prepare("INSERT INTO status_meta(k,v) VALUES('map_paused',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(paused ? '1' : '0').run();
        return json({ ok: true, paused });
      } catch (e) { return serverErr(e); }
    }

    if (url.pathname === '/api/rider-map/state' && request.method === 'GET') {
      const user = await getSessionUser(env, request);
      if (!user) return json({ error: 'unauthorized' }, 401);
      return json({ paused: await isMapPaused(env) });
    }

    if (url.pathname === '/api/riders' && request.method === 'GET') {
      const okMapToken = env.MAP_VIEW_TOKEN && safeEqual(request.headers.get('Authorization') || '', `Bearer ${env.MAP_VIEW_TOKEN}`);
      if (!okMapToken && !await getSessionUser(env, request)) return json({ error: 'unauthorized' }, 401);
      if (await isMapPaused(env)) return json({ paused: true, updated_at: null, riders: [] });
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
      if (await isMapPaused(env)) return json({ paused: true });
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

    // 27 Nov (24301978): reversible stand-down switch for the live status cron while the
    // Turso staging copy runs as the single notifier. GET reads, POST {on:bool} sets.
    if (url.pathname === '/api/admin/notif_pause' && (request.method === 'GET' || request.method === 'POST')) {
      await ensureSchema(env);
      const user = await getSessionUser(env, request);
      if (!user) return json({ error: 'unauthorized' }, 401);
      if (user.r !== 'admin') return json({ error: 'forbidden' }, 403);
      if (request.method === 'POST') {
        let on = null;
        try { const b = await request.json(); on = !!(b && b.on); } catch { return json({ error: 'bad_json' }, 400); }
        await env.DB.prepare("INSERT INTO settings(k,v) VALUES('notif_pause',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(on ? '1' : '0').run();
      }
      const p = await env.DB.prepare("SELECT v FROM settings WHERE k='notif_pause'").first();
      return json({ ok: true, paused: !!(p && p.v === '1') });
    }

    // 27 Nov (24301978): one-shot seed export for the Turso staging copy (users incl. roles,
    // push tokens, current rider states so staging's first cron sees no fake flips). Admin-only.
    if (url.pathname === '/api/admin/export_state' && request.method === 'GET') {
      await ensureSchema(env);
      const user = await getSessionUser(env, request);
      if (!user) return json({ error: 'unauthorized' }, 401);
      if (user.r !== 'admin') return json({ error: 'forbidden' }, 403);
      const users = await env.DB.prepare('SELECT * FROM users').all();
      const tokens = await env.DB.prepare('SELECT * FROM push_tokens').all();
      const states = await env.DB.prepare('SELECT * FROM rider_states').all();
      return json({ ok: true, users: users.results || [], push_tokens: tokens.results || [], rider_states: states.results || [] });
    }

    if (url.pathname === '/api/admin/usage' && request.method === 'GET') {
      try {
        await ensureSchema(env);
        const user = await getSessionUser(env, request);
        if (!user) return json({ error: 'unauthorized' }, 401);
        if (user.r !== 'admin') return json({ error: 'forbidden' }, 403);
        const reset = nextUtcMidnight();
        const day = utcDay();
        let cron = null;
        try {
          const lm = await env.DB.prepare("SELECT v FROM status_meta WHERE k='cron_lock_min'").first();
          const ld = await env.DB.prepare("SELECT v FROM status_meta WHERE k='cron_lock_morning'").first();
          cron = { minute_lock: lm && lm.v ? Number(lm.v) : null, minute_now: Math.floor(Date.now() / 60000), morning_lock: ld && ld.v ? ld.v : null };
        } catch {}
        // 27 Nov: status-cron stats + recent push failures, so notification health is checkable
        // without D1 console access. -4 = FCM not configured; other non-200 = FCM rejections.
        let status_cron = null, push_log = null, status_fetch_err = null;
        try {
          const sr = await env.DB.prepare("SELECT v FROM status_meta WHERE k='cron:status_stats'").first();
          if (sr && sr.v) status_cron = JSON.parse(sr.v);
          const fe = await env.DB.prepare("SELECT v FROM status_meta WHERE k='cron:status_fetch_err'").first();
          if (fe && fe.v) status_fetch_err = JSON.parse(fe.v);
        } catch {}
        try {
          const pr = await env.DB.prepare('SELECT u,token_tail,status,resp,ts FROM push_log ORDER BY ts DESC LIMIT 5').all();
          push_log = (pr.results || []).map(r => ({ u: r.u, tail: r.token_tail, status: r.status, resp: String(r.resp || '').slice(0, 160), ts: r.ts }));
        } catch {}
        // 27 Nov (Micheal 24167952): on-demand supervisor-scoping audit (?audit=1). Re-checks the
        // last 200 state-flip notifications: each must have gone ONLY to users matching the rider's
        // supervisor cell. Uses the rider's CURRENT sup (sups don't change during the flip test).
        let notif_audit = null;
        if (url.searchParams.get('audit') === '1') {
          try {
            const nrows = await env.DB.prepare("SELECT u, rider_id, ts FROM notifications WHERE title LIKE '%تغيير حالة%' ORDER BY id DESC LIMIT 200").all();
            const items = nrows.results || [];
            const riderIds = [...new Set(items.map(r => r.rider_id).filter(Boolean))];
            const supByRider = new Map();
            for (const rid of riderIds) {
              const rr = await env.DB.prepare('SELECT sup FROM rider_states WHERE rider_id=?').bind(rid).first();
              if (rr) supByRider.set(rid, rr.sup);
            }
            const supUsers = new Map();
            let checked = 0; const mismatches = [];
            for (const it of items) {
              const sup = supByRider.get(it.rider_id);
              if (!sup) continue; // rider no longer tracked - cannot verify
              if (!supUsers.has(sup)) {
                let sr = await env.DB.prepare("SELECT u FROM users WHERE status='active' AND (n=? OR u=?)").bind(sup, sup.toLowerCase()).all();
                if (!(sr.results || []).length) sr = await env.DB.prepare("SELECT u FROM users WHERE status='active' AND n LIKE ?").bind('%' + sup.replace(/%/g, '') + '%').all();
                supUsers.set(sup, new Set((sr.results || []).map(x => x.u)));
              }
              checked++;
              if (!supUsers.get(sup).has(it.u)) mismatches.push({ u: it.u, rider_id: it.rider_id, sup, ts: it.ts });
            }
            notif_audit = { window: items.length, checked, mismatch_count: mismatches.length, mismatches: mismatches.slice(0, 20) };
          } catch (e) { notif_audit = { error: String(e).slice(0, 200) }; }
        }
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
            return json({ ok: true, source: 'cloudflare', scope: 'account', limit: QUOTA_DAILY_LIMIT, used, remaining: Math.max(0, QUOTA_DAILY_LIMIT - used), day, hiring, cron, status_cron, push_log, notif_audit, status_fetch_err, reset_at: reset.toISOString() });
          } catch (e) {
            const used = await usageEstimate(env);
            return json({ ok: true, source: 'estimate', scope: 'worker', cloudflare_error: String(e && e.message || e).slice(0, 200), limit: QUOTA_DAILY_LIMIT, used, remaining: Math.max(0, QUOTA_DAILY_LIMIT - used), day, hiring, cron, status_cron, push_log, notif_audit, status_fetch_err, reset_at: reset.toISOString() });
          }
        }
        const used = await usageEstimate(env);
        return json({ ok: true, source: 'estimate', scope: 'worker', limit: QUOTA_DAILY_LIMIT, used, remaining: Math.max(0, QUOTA_DAILY_LIMIT - used), day, hiring, cron, status_cron, push_log, notif_audit, status_fetch_err, reset_at: reset.toISOString() });
      } catch (e) {
        return serverErr(e);
      }
    }

    // static assets: worker runs first (run_worker_first), so fetch from the assets binding
    // 27 Nov: staging has no assets binding - answer plainly instead of throwing (1101).
    if ((request.method === 'GET' || request.method === 'HEAD') && env.ASSETS) {
      const assetResp = await env.ASSETS.fetch(request);
      if (assetResp.status !== 404) {
        const ct = assetResp.headers.get('Content-Type') || '';
        return withSec(assetResp, /text\/html/.test(ct));
      }
    }
    if (!env.ASSETS && (url.pathname === '/' || url.pathname === '/index.html')) return new Response('team-mh staging worker OK (no assets)', { status: 200 });
    return json({ error: 'not_found' }, 404);
}

async function handleScheduled(event, rawEnv, ctx) {
    const env = withDb(rawEnv);
    bumpUsage(env, ctx);
    // 26 Nov cron dedup (Micheal 22473910): same code runs at two addresses (team-mh + riders-map-relay)
    // on ONE D1, so every cron fired twice. Claim the slot first; only the claimer works. 1 write/min total.
    const jobs = [];
    if (event.cron !== '0 7 * * *' && await claimCronSlot(env, 'cron_lock_min', Math.floor(Date.now() / 60000))) {
      jobs.push(runStatusCron(env).catch(() => {}));
      jobs.push(runScheduleCron(env).catch(() => {}));
      jobs.push(runStoppedRiderCron(env).catch(() => {}));
    }
    if (event.cron === '0 7 * * *' && await claimCronSlot(env, 'cron_lock_morning', utcDay())) jobs.push(runMorningSummary(env, false).catch(() => {}));
    ctx.waitUntil(Promise.all(jobs));
}

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
