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
    env.DB.prepare(`CREATE INDEX IF NOT EXISTS form_submissions_user_ts ON form_submissions(u,ts)`),
  ]);
  try { await env.DB.prepare("ALTER TABLE users ADD COLUMN photo TEXT NOT NULL DEFAULT ''").run(); } catch {}
  schemaReady = true;
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
    const user = await env.DB.prepare('SELECT * FROM users WHERE u=?').bind(u).first();
    if (!user || user.status === 'disabled') return json({ error: 'invalid_credentials' }, 401);
    if (user.status === 'suspended') return json({ error: 'suspended' }, 403);
    if (!safeEqual(user.h, await hp(u, String(body.p)))) {
      await env.DB.prepare('INSERT INTO login_fails(u,n) VALUES(?,1) ON CONFLICT(u) DO UPDATE SET n=n+1').bind(u).run();
      const f = await env.DB.prepare('SELECT n FROM login_fails WHERE u=?').bind(u).first();
      if (f && f.n >= 5) {
        await env.DB.prepare("UPDATE users SET status='suspended', updated_at=? WHERE u=?").bind(Date.now(), u).run();
        await env.DB.prepare('DELETE FROM sessions WHERE u=?').bind(u).run();
        return json({ error: 'suspended' }, 403);
      }
      return json({ error: 'invalid_credentials', attempts_left: 5 - (f ? f.n : 1) }, 401);
    }
    await env.DB.prepare('DELETE FROM login_fails WHERE u=?').bind(u).run();
    await enforceDeviceLimit(env, u, 4);
    const token = await issueSession(env, u, !!body.remember);
    await env.DB.prepare('DELETE FROM rl WHERE k=?').bind('login:' + u).run();
    return json({ token, profile: profile(user) });
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
    const chk = await verifyCode(env, u, 'login', body.code);
    if (chk !== 'ok') return json({ error: chk === 'expired' ? 'code_expired' : 'invalid_code' }, 401);
    const token = await issueSession(env, u, !!body.remember);
    return json({ token, profile: profile(user) });
  }

  if (p === '/api/auth/forgot' && request.method === 'POST') {
    if (!body || !body.u) return json({ error: 'missing_fields' }, 400);
    const u = String(body.u).toLowerCase().slice(0, 60);
    const wait = await rateLimit(env, 'forgot:' + u, 3, 60 * 60 * 1000, 30 * 60 * 1000);
    if (wait) return json({ error: 'locked', wait }, 429);
    const user = await env.DB.prepare('SELECT * FROM users WHERE u=?').bind(u).first();
    if (user && user.status !== 'disabled' && (user.email || user.phone)) {
      const code = await makeCode(env, u, 'reset', 8, 60 * 60 * 1000);
      const text = 'أهلًا ' + user.n + ',\n\nكود إعادة تعيين كلمة المرور: ' + code + '\nصالح لمدة ساعة.\n\nلو مش انت اللي طلبت، كلم الأدمن فورًا.';
      let sent = false, via = '';
      if (user.email && user.channel !== 'whatsapp') {
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
    await env.DB.prepare('UPDATE users SET h=?, updated_at=? WHERE u=?').bind(await hp(u, p2), Date.now(), u).run();
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
    if (user) await env.DB.prepare('DELETE FROM sessions WHERE token=?').bind(user.token).run();
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
            .bind(u, n, r, s, await hp(u, String(body.p)), Date.now(), rename).run();
          await env.DB.prepare('UPDATE sessions SET u=? WHERE u=?').bind(u, rename).run();
          return json({ ok: true });
        }
        if (!existing) return json({ error: 'not_found' }, 404);
        if (body.p) await env.DB.prepare('UPDATE users SET n=?, r=?, s=?, h=?, updated_at=? WHERE u=?').bind(n, r, s, await hp(u, String(body.p)), Date.now(), u).run();
        else await env.DB.prepare('UPDATE users SET n=?, r=?, s=?, updated_at=? WHERE u=?').bind(n, r, s, Date.now(), u).run();
        return json({ ok: true });
      }
      if (existing) {
        if (body.p) await env.DB.prepare('UPDATE users SET n=?, r=?, s=?, h=?, updated_at=? WHERE u=?').bind(n, r, s, await hp(u, String(body.p)), Date.now(), u).run();
        else await env.DB.prepare('UPDATE users SET n=?, r=?, s=?, updated_at=? WHERE u=?').bind(n, r, s, Date.now(), u).run();
        return json({ ok: true });
      }
      const p2 = body.p ? String(body.p) : randPassword();
      await env.DB.prepare('INSERT INTO users(u,n,r,s,h,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)')
        .bind(u, n, r, s, await hp(u, p2), 'active', Date.now(), Date.now()).run();
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

export default {
  async fetch(request, env) {
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
      headers: { ...cors, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
    });
    const url = new URL(request.url);
    const hub = env.RIDER_MAP_HUB.get(env.RIDER_MAP_HUB.idFromName('riders-global'));

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
      if (!['extend','break'].includes(action)) return json({error:'bad_action'},400);
      await ensureSchema(env);
      const since=Date.now()-48*3600000;
      const query=user.r==='admin'
        ?env.DB.prepare('SELECT id,u,action,rider_id,city,payload,result,ts FROM form_submissions WHERE action=? AND ts>=? ORDER BY ts DESC LIMIT 1000').bind(action,since)
        :env.DB.prepare('SELECT id,u,action,rider_id,city,payload,result,ts FROM form_submissions WHERE action=? AND ts>=? AND u=? ORDER BY ts DESC LIMIT 1000').bind(action,since,user.u);
      const data=await query.all();
      const today=cairoDay();
      return json({day:today,scope:user.r==='admin'?'all':'own',rows:(data.results||[]).filter(r=>cairoDay(r.ts)===today).map(r=>{let p={},v={};try{p=JSON.parse(r.payload)}catch{}try{v=JSON.parse(r.result)}catch{}return {id:r.id,u:r.u,rider_id:r.rider_id,city:r.city,ts:r.ts,duration:p.duration||p['entry.1552166535']||((p['entry.536642639_hour']||'')+':'+(p['entry.536642639_minute']||'')),reason:p.reason||p['entry.1831411232']||'',confirmed:v.ok===true,status:v.status||null}})});
    }

    if (url.pathname === '/api/forms/submit' && request.method === 'POST') {
      const user = await getSessionUser(env, request);
      if (!user) return json({ error: 'unauthorized' }, 401);
      if (!['admin', 'manager', 'sup'].includes(user.r)) return json({ error: 'forbidden' }, 403);
      const body = await request.json().catch(() => ({}));
      const action = String(body.action || '');
      const riderId = String(body.rider_id || '').replace(/[^0-9]/g, '');
      const city = String(body.city || '').trim();
      const duration = String(body.duration || '').trim();
      const reason = String(body.reason || '').trim();
      const zone = String(body.zone || '').trim();
      if (!['extend', 'break'].includes(action)) return json({ error: 'bad_action' }, 400);
      if (!riderId) return json({ error: 'bad_rider' }, 400);
      if (!city) return json({ error: 'bad_city' }, 400);
      if (action === 'extend' && !duration) return json({ error: 'bad_duration' }, 400);
      const isAlex = city === 'الإسكندرية';
      if (action === 'break' && isAlex && !reason) return json({ error: 'bad_reason' }, 400);
      const relayUrl = isAlex ? env.FORM_RELAY_ALEX : env.FORM_RELAY_GENERAL;
      if (!relayUrl || !env.FORM_RELAY_SECRET) return json({ error: 'relay_not_configured' }, 503);
      const cityVal = zone || (city === 'الغردقة' ? 'الغرادقه' : city);
      let fields, pageHistory;
      if (isAlex) {
        const m = action === 'break' ? ['','0','00',''] : duration.match(/^(\d{1,2}):(\d{2})$/) || duration.match(/(\d{1,2}):(\d{2})\s*(الفجر|الصبح|الضهر|العصر|بليل)/);
        if (!m) return json({ error: 'bad_duration_format' }, 400);
        let hh = parseInt(m[1], 10);if(hh>23||+m[2]>59)return json({error:'bad_duration_format'},400);
        if (m[3] === 'الضهر' || m[3] === 'العصر') { if (hh !== 12) hh += 12; }
        if (m[3] === 'بليل') { hh = hh === 12 ? 0 : hh + 12; }
        if (action === 'extend') {
          fields = { 'entry.1976663790': 'شيفتات الطيارين', 'entry.186608000': riderId, 'entry.2117629487': 'تزويدات شيفتات الطيارين', 'entry.536642639_hour': String(hh), 'entry.536642639_minute': m[2] };
          pageHistory = '0,1,2';
        } else {
          fields = { 'entry.1976663790': 'شيفتات الطيارين', 'entry.186608000': riderId, 'entry.2117629487': 'البريكات', 'entry.1290442973': 'فك بريك', 'entry.1831411232': reason };
          pageHistory = '0,1,15';
        }
      } else if (action === 'extend') {
        fields = { 'entry.302135773': 'شيفتات الطيارين', 'entry.1941659317': 'تزويدات شيفتات الطيارين', 'entry.1552166535': duration, 'entry.1026285494': riderId, 'entry.1529435164': cityVal };
        pageHistory = '0,1,2';
      } else {
        fields = { 'entry.302135773': 'شيفتات الطيارين', 'entry.1941659317': 'فك بريك', 'entry.264752225': riderId, 'entry.1551386634': cityVal };
        pageHistory = '0,1,6';
      }
      const resp = await fetch(relayUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ secret: env.FORM_RELAY_SECRET, formId: isAlex ? '1FAIpQLSffSwyTh0w4AYjTU9AG-kj-0UfJHcSTSYnR1DrWJ_h8iPYm3Q' : '1FAIpQLSekxaUQPgiWq-Y_IPfsTx7wTANA324a2JklFJZ_Gxg9CGPaKA', fields, pageHistory }) });
      const result = await resp.json().catch(() => ({error:'invalid_relay_response'}));
      let logSaved=true;
      try { await ensureSchema(env);await env.DB.prepare('INSERT INTO form_submissions(u,action,rider_id,city,payload,result,ts) VALUES(?,?,?,?,?,?,?)').bind(user.u, action, riderId, city, JSON.stringify({...fields,duration,reason}), JSON.stringify(result), Date.now()).run(); } catch (e) {logSaved=false;}
      if (!resp.ok || result.ok !== true || result.error || (result.status && result.status >= 400)) return json({ error: 'relay_failed', detail: result.error || ('HTTP ' + (result.status || resp.status)) }, 502);
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

    // static assets are served automatically by the assets binding before this
    return json({ error: 'not_found' }, 404);
  },

  async scheduled(event, env, ctx) {
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
