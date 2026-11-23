// wa-gw: minimal WhatsApp Web gateway (Baileys) with a token-secured send queue.
// Env: GATEWAY_TOKEN (required), PORT (default 8787), AUTH_DIR (default ./auth)
const http = require('http');
const fs = require('fs');
const path = require('path');
const QRCode = require('qrcode');
const { default: makeWASocket, useMultiFileAuthState, DisconnectReason, fetchLatestBaileysVersion } = require('@whiskeysockets/baileys');

const TOKEN = process.env.GATEWAY_TOKEN || '';
const PORT = parseInt(process.env.PORT || '8787', 10);
const AUTH_DIR = process.env.AUTH_DIR || path.join(__dirname, 'auth');
if (!TOKEN) { console.error('GATEWAY_TOKEN is required'); process.exit(1); }

let sock = null;
let connState = 'starting'; // starting | qr | connected | disconnected
let lastQR = null;
let lastQRAt = 0;
let queue = [];
let sending = false;
let currentItem = null;
let lastError = '';
const log = [];
function note(m) { log.push({ t: Date.now(), m }); if (log.length > 200) log.shift(); console.log(m); }
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function startWA() {
  const { state, saveCreds } = await useMultiFileAuthState(AUTH_DIR);
  const { version } = await fetchLatestBaileysVersion().catch(() => ({ version: undefined }));
  sock = makeWASocket({
    version,
    auth: state,
    printQRInTerminal: false,
    browser: ['TeamMH Bot', 'Chrome', '1.0'],
    logger: { level: 'silent', trace(){}, debug(){}, info(){}, warn(){}, error(){}, fatal(){}, child(){ return this; } },
  });
  sock.ev.on('creds.update', saveCreds);
  sock.ev.on('connection.update', u => {
    if (u.qr) { lastQR = u.qr; lastQRAt = Date.now(); connState = 'qr'; note('QR ready'); }
    if (u.connection === 'open') { connState = 'connected'; lastQR = null; note('connected'); }
    if (u.connection === 'close') {
      const code = u.lastDisconnect && u.lastDisconnect.error && u.lastDisconnect.error.output ? u.lastDisconnect.error.output.statusCode : 0;
      const loggedOut = code === DisconnectReason.loggedOut;
      connState = 'disconnected';
      note('connection closed code=' + code + (loggedOut ? ' (logged out)' : ''));
      if (loggedOut) { try { fs.rmSync(AUTH_DIR, { recursive: true, force: true }); } catch (e) {} }
      setTimeout(() => startWA().catch(e => note('restart error: ' + e.message)), loggedOut ? 1000 : 5000);
    }
  });
}

async function pump() {
  if (sending) return;
  sending = true;
  while (queue.length) {
    const item = queue[0];
    currentItem = { to: item.to, text: item.text.slice(0, 60) };
    if (connState !== 'connected') { note('waiting for connection...'); await sleep(5000); continue; }
    try {
      const jid = item.to.replace(/\D/g, '') + '@s.whatsapp.net';
      try { await sock.sendPresenceUpdate('composing', jid); await sleep(1500 + Math.random() * 1500); } catch (e) {}
      await sock.sendMessage(jid, { text: item.text });
      item.ok = true; item.doneAt = Date.now();
      note('sent -> ' + item.to);
      queue.shift();
      const wait = (item.delaySec * 1000) + Math.floor(Math.random() * item.jitterSec * 1000);
      if (queue.length) await sleep(wait);
    } catch (e) {
      item.ok = false; item.error = String(e && e.message || e); item.doneAt = Date.now();
      note('FAILED -> ' + item.to + ' : ' + item.error);
      queue.shift();
      await sleep(3000);
    }
  }
  currentItem = null;
  sending = false;
}

function statusObj() {
  return {
    state: connState,
    sending,
    pending: queue.length,
    current: currentItem,
    lastError,
    recent: log.slice(-30),
    qr: (connState === 'qr' && lastQR) ? true : false,
  };
}

const server = http.createServer(async (req, res) => {
  const send = (code, obj) => { res.writeHead(code, { 'content-type': 'application/json', 'cache-control':'no-store' }); res.end(JSON.stringify(obj)); };
  if (req.method === 'OPTIONS') { res.writeHead(204, { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'authorization,content-type', 'access-control-allow-methods': 'GET,POST,OPTIONS' }); return res.end(); }
  const auth = (req.headers.authorization || '') === 'Bearer ' + TOKEN;
  const url = new URL(req.url, 'http://x');
  if (req.method === 'GET' && url.pathname === '/') { res.writeHead(200, { 'content-type':'text/html; charset=utf-8', 'cache-control':'no-store', 'referrer-policy':'no-referrer', 'x-frame-options':'DENY' }); return res.end('<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TEAM MH | ربط واتساب</title><style>body{margin:0;background:#101827;color:#edf2fa;font:17px system-ui}main{max-width:460px;margin:45px auto;padding:24px}h1{font-size:26px}p{line-height:1.7;color:#bac8da}input,button{box-sizing:border-box;width:100%;padding:14px;margin:8px 0;border-radius:10px;border:1px solid #40506a;font:inherit}input{background:#1b293e;color:white}button{background:#2dc19f;color:#06231b;cursor:pointer}img{display:block;width:300px;max-width:100%;margin:22px auto;border:10px solid white;border-radius:8px}#state{padding:14px;background:#1b293e;border-radius:10px}</style><main><h1>TEAM MH | ربط واتساب</h1><p>أدخل مفتاح البوابة المحفوظ، ثم اعرض رمز الربط. المفتاح لا يُحفظ في المتصفح ولا يظهر في الرابط.</p><label for="token">مفتاح البوابة</label><input id="token" type="password" autocomplete="off"><button id="load">عرض رمز الربط / تحديث الحالة</button><p id="state">لم يتم طلب الرمز بعد.</p><img id="qr" hidden alt="رمز ربط واتساب"><p>من واتساب: الإعدادات ← الأجهزة المرتبطة ← ربط جهاز. لا تُشارك صورة الرمز أو المفتاح مع أي شخص.</p><p>الاستضافة مجانية بحد استخدام، وقد تتوقف عند نفاد الرصيد. هذه الصفحة لا ترسل رسائل.</p></main><script>const button=document.getElementById(\'load\');button.onclick=async()=>{const status=document.getElementById(\'state\'),img=document.getElementById(\'qr\');button.disabled=true;img.hidden=true;try{const r=await fetch(\'/qr\',{headers:{Authorization:\'Bearer \'+document.getElementById(\'token\').value},cache:\'no-store\'});if(!r.ok)throw new Error(r.status===401?\'المفتاح غير صحيح\':\'تعذر الاتصال بالبوابة\');const d=await r.json();status.textContent=d.state===\'connected\'?\'تم ربط واتساب بنجاح\':d.qr?\'امسح الرمز من واتساب. لو انتهت صلاحيته اضغط تحديث.\':\'الرمز غير جاهز. اضغط تحديث بعد قليل.\';if(d.qr){img.src=d.qr;img.hidden=false}}catch(e){status.textContent=e.message}finally{button.disabled=false}};</script></html>'); }
  if (url.pathname === '/health') return send(200, { ok: true, state: connState });
  if (!auth) return send(401, { error: 'unauthorized' });
  const body = req.method === 'POST' ? await new Promise(r => { let d = ''; req.on('data', c => d += c); req.on('end', () => { try { r(JSON.parse(d || '{}')); } catch (e) { r({}); } }); }) : {};

  if (url.pathname === '/qr') {
    if (connState === 'qr' && lastQR) { const img = await QRCode.toDataURL(lastQR, { margin: 1, width: 300 }); return send(200, { state: connState, qr: img }); }
    return send(200, { state: connState, qr: null });
  }
  if (url.pathname === '/status') return send(200, statusObj());
  if (url.pathname === '/send-batch' && req.method === 'POST') {
    const msgs = Array.isArray(body.messages) ? body.messages : [];
    const delaySec = Math.min(300, Math.max(15, parseInt(body.delaySec, 10) || 45));
    const jitterSec = Math.min(120, Math.max(0, parseInt(body.jitterSec, 10) || 30));
    const cap = Math.min(200, Math.max(1, parseInt(body.cap, 10) || 50));
    const valid = [];
    for (const m of msgs) {
      const to = String(m && m.to || '').replace(/\D/g, '');
      const text = String(m && m.text || '').trim().slice(0, 1000);
      if (/^\d{10,15}$/.test(to) && text) valid.push({ to, text, delaySec, jitterSec });
      if (valid.length >= cap) break;
    }
    queue.push(...valid);
    note('enqueued ' + valid.length + ' (delay ' + delaySec + 's+' + jitterSec + 's jitter, cap ' + cap + ')');
    pump();
    return send(200, { enqueued: valid.length, skipped: msgs.length - valid.length });
  }
  if (url.pathname === '/stop' && req.method === 'POST') {
    const n = queue.length; queue = [];
    note('stopped, cleared ' + n);
    return send(200, { cleared: n });
  }
  if (url.pathname === '/logout' && req.method === 'POST') {
    try { await sock.logout(); } catch (e) {}
    return send(200, { ok: true });
  }
  return send(404, { error: 'not_found' });
});

startWA().catch(e => { lastError = String(e && e.message || e); note('start error: ' + lastError); });
server.listen(PORT, () => note('wa-gw listening on :' + PORT));
