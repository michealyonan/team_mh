// team_mh Desktop v0.3.0 - Electron main process.
// The window loads the team_mh site. مد الشيفت / فك البريك run DIRECTLY on this
// machine: a button tap drives the installed Chrome (persistent per-group profile,
// like Micheal's Python tool) - no server queue, no polling. Result shows as a local
// notification + in the dialog; a best-effort log line is posted to the site.
const { app, BrowserWindow, shell, Notification, ipcMain } = require('electron');
const fs = require('fs');
const path = require('path');
const { autoUpdater } = require('electron-updater');
const { getBrowser } = require('./chromeproc');
const { runFormWalk } = require('./chromewalk');

const VERSION = '0.3.0';
const SITE = 'https://team-mh.michealuonanayad.workers.dev';
const FORMS = {
  alex: { url: 'https://docs.google.com/forms/u/0/d/e/1FAIpQLSffSwyTh0w4AYjTU9AG-kj-0UfJHcSTSYnR1DrWJ_h8iPYm3Q/viewform', email: 'alexlogistics.teammh101@gmail.com' },
  delta: { url: 'https://docs.google.com/forms/u/0/d/e/1FAIpQLSekxaUQPgiWq-Y_IPfsTx7wTANA324a2JklFJZ_Gxg9CGPaKA/viewform', email: 'deltalogistics.teammh1@gmail.com' }
};
const SIGNIN_WAIT_MS = 6 * 60 * 1000;
const WALK_WATCHDOG_MS = 150000;
const SPACING_MS = 60000; // small local anti-burst spacing between submissions

let mainWin = null;
let cmdWin = null;
let busy = false;
let lastRunAt = 0;

function statePath() { return path.join(app.getPath('userData'), 'google-signin-state.json'); }
function readState() {
  try { return JSON.parse(fs.readFileSync(statePath(), 'utf8')); } catch (e) { return {}; }
}
function writeState(s) {
  try { fs.writeFileSync(statePath(), JSON.stringify(s)); } catch (e) {}
}
function pushState() {
  for (const w of [mainWin, cmdWin]) {
    if (w && !w.isDestroyed()) { try { w.webContents.send('tmh-google-state', readState()); } catch (e) {} }
  }
}
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
function notify(title, body) { try { new Notification({ title, body }).show(); } catch (e) {} }
function progress(stage, extra) {
  if (cmdWin && !cmdWin.isDestroyed()) {
    try { cmdWin.webContents.send('tmh-run-progress', Object.assign({ stage }, extra || {})); } catch (e) {}
  }
}

function createWindow() {
  mainWin = new BrowserWindow({
    width: 1320,
    height: 900,
    autoHideMenuBar: true,
    icon: __dirname + '/icon.png',
    webPreferences: { contextIsolation: true, sandbox: true, preload: __dirname + '/preload.js' }
  });
  mainWin.loadURL(SITE);
  mainWin.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });
  mainWin.webContents.on('did-finish-load', () => { injectPanel(); });
}

// Collapsible floating panel (Micheal 24 Nov: one small ⚡ tab; panel opens on tap and
// closes after). Desktop-only; the website itself is unchanged.
function injectPanel() {
  const js = `
(function(){
  if (window.__tmhPanel || !window.tmhDesktop) return;
  window.__tmhPanel = 1;
  var tab = document.createElement('button');
  tab.textContent = '⚡';
  tab.title = 'team_mh';
  tab.style.cssText = 'position:fixed;bottom:16px;inset-inline-start:16px;z-index:99998;width:46px;height:46px;border-radius:50%;background:#16a34a;color:#fff;border:0;font-size:22px;cursor:pointer;box-shadow:0 6px 18px #0008';
  var box = document.createElement('div');
  box.style.cssText = 'position:fixed;bottom:74px;inset-inline-start:16px;z-index:99999;background:#0f172a;border:1px solid #334155;border-radius:14px;padding:10px 12px;color:#e2e8f0;font-family:Cairo,system-ui,sans-serif;font-size:13px;box-shadow:0 8px 24px #0009;min-width:230px;display:none';
  function row(which,label){
    return '<div style="display:flex;align-items:center;gap:8px;margin:4px 0">'
      + '<button data-tmh="' + which + '" style="flex:1;background:#1d4ed8;color:#fff;border:0;border-radius:10px;padding:8px 10px;font:inherit;font-weight:700;cursor:pointer">' + label + '</button>'
      + '<span data-tmh-st="' + which + '" style="font-size:11px;color:#94a3b8;max-width:110px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">…</span></div>';
  }
  box.innerHTML = '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px">'
    + '<div style="font-weight:800">🔐 دخول جوجل للفورم</div>'
    + '<button data-tmh-close="1" style="background:none;border:0;color:#94a3b8;font-size:16px;cursor:pointer">✕</button></div>'
    + row('alex','تسجيل دخول (اسكندرية)')
    + row('delta','تسجيل دخول (باقي المحافظات)')
    + '<button data-tmh-cmd="1" style="width:100%;margin-top:8px;background:#16a34a;color:#fff;border:0;border-radius:10px;padding:10px;font:inherit;font-weight:900;cursor:pointer">⚡ مد الشيفت / فك البريك</button>'
    + '<div style="font-size:10px;color:#475569;margin-top:6px">v${VERSION}</div>';
  document.body.appendChild(tab);
  document.body.appendChild(box);
  function paint(st){
    st = st || {};
    ['alex','delta'].forEach(function(w){
      var el = box.querySelector('[data-tmh-st="' + w + '"]');
      if (!el) return;
      var acc = st[w] && st[w].account;
      el.textContent = acc ? ('✅ ' + acc) : 'مش مسجل';
      el.style.color = acc ? '#4ade80' : '#94a3b8';
      el.title = acc || '';
    });
  }
  tab.addEventListener('click', function(){
    box.style.display = box.style.display === 'none' ? '' : 'none';
    if (box.style.display !== 'none') window.tmhDesktop.getState().then(paint).catch(function(){});
  });
  box.addEventListener('click', function(ev){
    if (ev.target.closest('[data-tmh-close]')) { box.style.display = 'none'; return; }
    var b = ev.target.closest('button[data-tmh]');
    if (b) window.tmhDesktop.signin(b.getAttribute('data-tmh'));
    if (ev.target.closest('button[data-tmh-cmd]')) { window.tmhDesktop.openCommands(); box.style.display = 'none'; }
  });
  window.tmhDesktop.onState(paint);
})();`;
  try { mainWin.webContents.executeJavaScript(js); } catch (e) {}
}

// Google sign-in per group, inside that group's dedicated real-Chrome profile.
async function openGoogleSignin(which) {
  const cfg = FORMS[which];
  if (!cfg) return;
  notify('team_mh', 'كروم هيفتح - سجّل دخول جوجل بالحساب ' + cfg.email + ' مرة واحدة والتطبيق هيكمل لوحده');
  let browser;
  try { browser = await getBrowser(which, app.getPath('userData')); }
  catch (e) { notify('team_mh ❌', 'مش قادر أفتح كروم على الجهاز ده'); return; }
  const page = await browser.newPage();
  try { await page.goto(cfg.url, { waitUntil: 'domcontentloaded', timeout: 60000 }); } catch (e) {}
  const deadline = Date.now() + SIGNIN_WAIT_MS;
  while (Date.now() < deadline) {
    let url = '';
    try { url = page.url(); } catch (e) { return; } // tab closed by Micheal
    if (/docs\.google\.com\/forms/.test(url)) {
      let acct = '';
      try { acct = String(await page.evaluate(accountFromPageFn) || '').toLowerCase(); } catch (e) {}
      if (acct) {
        const st = readState();
        st[which] = { account: acct, at: Date.now() };
        writeState(st);
        pushState();
        notify('team_mh ✅', 'تم تسجيل الدخول: ' + acct);
        try { await page.close(); } catch (e) {}
        return;
      }
    }
    await sleep(2000);
  }
}

function accountFromPageFn() {
  const m = document.documentElement.innerHTML.match(/([a-zA-Z0-9._%+-]+@(?!google\.com)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  return m ? m[1] : '';
}

ipcMain.on('tmh-google-signin', (_e, which) => { openGoogleSignin(String(which)); });
ipcMain.handle('tmh-google-state', () => readState());

function openCommands() {
  if (cmdWin && !cmdWin.isDestroyed()) { cmdWin.show(); cmdWin.focus(); return; }
  cmdWin = new BrowserWindow({
    width: 440,
    height: 660,
    parent: mainWin,
    icon: __dirname + '/icon.png',
    autoHideMenuBar: true,
    webPreferences: { contextIsolation: true, sandbox: true, preload: __dirname + '/preload.js' }
  });
  cmdWin.on('closed', () => { cmdWin = null; });
  cmdWin.loadFile(__dirname + '/commands.html');
}
ipcMain.on('tmh-open-commands', () => { openCommands(); });

async function getToken() {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      if (!mainWin || mainWin.isDestroyed()) return '';
      const t = await mainWin.webContents.executeJavaScript(
        "(sessionStorage.getItem('pd_token')||localStorage.getItem('pd_remember_login')||'')");
      if (typeof t === 'string' && t) return t;
    } catch (e) {}
    if (attempt === 0) await sleep(600);
  }
  return '';
}

async function api(p, opts) {
  const t = await getToken();
  const headers = { 'Content-Type': 'application/json' };
  if (t) headers.Authorization = 'Bearer ' + t;
  const r = await fetch(SITE + p, {
    method: (opts && opts.method) || 'GET',
    headers,
    body: opts && opts.body ? JSON.stringify(opts.body) : undefined
  });
  const d = await r.json().catch(() => null);
  if (!r.ok) { const e = new Error((d && d.error) || ('HTTP ' + r.status)); e.status = r.status; throw e; }
  return d;
}

// Best-effort site log: never blocks, never fails the run.
function logDirect(entry) {
  api('/api/forms/log-direct', { method: 'POST', body: entry }).catch(() => {});
}

// Parse duration inputs into the pieces the walk needs.
// Alex dialog gives 24h "HH:MM"; Delta gives a label like "إلي 01:00 الفجر".
function parseDuration(action, isAlex, duration) {
  if (action !== 'extend') return {};
  const m = String(duration || '').match(/(\d{1,2}):(\d{2})/);
  if (!m) return { error: 'bad_duration_format' };
  let hh = parseInt(m[1], 10);
  const mm = m[2];
  if (hh > 23 || +mm > 59) return { error: 'bad_duration_format' };
  let isPm;
  if (isAlex) {
    isPm = hh >= 12;
  } else {
    const d = String(duration);
    isPm = /الظهر|الضهر|العصر|بليل|مساء/.test(d) && !/صباح|الصبح|الفجر/.test(d);
  }
  let hh24 = hh;
  if (isPm && hh < 12) hh24 = hh + 12;
  if (!isPm && hh === 12 && !isAlex) hh24 = 0; // 12 ص = منتصف الليل (Delta labels)
  if (!isPm && hh === 12 && isAlex) hh24 = 0;
  const hh12v = hh % 12 === 0 ? 12 : hh % 12;
  return { hh12: String(hh12v), mm, isPm, hh24: String(hh24) };
}

ipcMain.handle('tmh-run-local', async (_e, payload) => {
  const p = payload || {};
  const action = String(p.action || '');
  const riderId = String(p.rider_id || '').replace(/[^0-9]/g, '');
  const city = String(p.city || '').trim();
  const zone = String(p.zone || '').trim();
  const duration = String(p.duration || '').trim();
  const reason = String(p.reason || '').trim();
  if (!['extend', 'break'].includes(action)) return { ok: false, error: 'bad_action' };
  if (!riderId) return { ok: false, error: 'bad_rider' };
  if (!city) return { ok: false, error: 'bad_city' };
  if (action === 'extend' && !duration) return { ok: false, error: 'bad_duration' };
  const isAlex = city === 'الإسكندرية';
  if (action === 'break' && isAlex && !reason) return { ok: false, error: 'bad_reason' };
  const dur = parseDuration(action, isAlex, duration);
  if (dur.error) return { ok: false, error: dur.error };
  const cityVal = zone || (city === 'الغردقة' ? 'الغرادقه' : city);
  const label = (action === 'break' ? 'فك بريك' : 'مد الشيفت') + ' - ' + riderId;

  if (busy) return { ok: false, error: 'busy' };
  busy = true;
  try {
    // Small local anti-burst spacing between submissions (protects the form accounts).
    const waitMs = SPACING_MS - (Date.now() - lastRunAt);
    if (waitMs > 0) {
      progress('spacing', { seconds: Math.ceil(waitMs / 1000) });
      await sleep(waitMs);
    }
    lastRunAt = Date.now();

    const group = isAlex ? 'alex' : 'delta';
    const cfg = FORMS[group];
    progress('launch', {});
    let browser;
    try { browser = await getBrowser(group, app.getPath('userData')); }
    catch (e) {
      notify('team_mh ❌', 'مش لاقي جوجل كروم على الجهاز - نزّله الأول');
      return { ok: false, error: 'chrome_not_found' };
    }
    const page = await browser.newPage();
    try {
      try { await page.goto(cfg.url, { waitUntil: 'domcontentloaded', timeout: 60000 }); }
      catch (e) { return { ok: false, error: 'page_load_failed', detail: String(e).slice(0, 200), submitted: false }; }

      // If Google asks for sign-in, leave the window open and wait for Micheal.
      let url = page.url();
      if (/accounts\.google\.com/.test(url)) {
        progress('signin_wait', { email: cfg.email });
        notify('team_mh', 'سجّل دخول جوجل بالحساب ' + cfg.email + ' في نافذة كروم - والتنفيذ هيكمل لوحده');
        const deadline = Date.now() + SIGNIN_WAIT_MS;
        while (Date.now() < deadline && /accounts\.google\.com/.test(url)) {
          await sleep(2000);
          try { url = page.url(); } catch (e) { return { ok: false, error: 'tab_closed', submitted: false }; }
        }
        if (/accounts\.google\.com/.test(url)) return { ok: false, error: 'auth_expired', detail: 'google sign-in not completed in time', submitted: false };
      }

      // Wrong-account guard (Micheal 24 Nov: alexlogistics = Alex, deltalogistics = 6 cities).
      let acct = '';
      try { acct = String(await page.evaluate(accountFromPageFn) || '').toLowerCase(); } catch (e) {}
      if (acct) {
        const st = readState();
        st[group] = { account: acct, at: Date.now() };
        writeState(st);
        pushState();
        if (acct !== cfg.email) {
          notify('team_mh ❌', 'الحساب المسجل (' + acct + ') مش حساب الفورم. سجّل دخول بالحساب ' + cfg.email);
          return { ok: false, error: 'wrong_account', detail: 'signed in as ' + acct + ', expected ' + cfg.email, submitted: false };
        }
      }

      progress('walking', {});
      const job = Object.assign({ isAlex, action, riderId, city, zone, cityVal, reason, duration }, dur);
      const res = await Promise.race([
        runFormWalk(page, job),
        sleep(WALK_WATCHDOG_MS).then(() => ({ ok: false, error: 'watchdog_timeout', submitted: false }))
      ]);
      lastRunAt = Date.now();
      if (res && res.ok) notify('team_mh ✅', 'تم: ' + label);
      else notify('team_mh ❌', 'فشل: ' + label + ' (' + ((res && res.error) || 'unknown') + ')');
      logDirect({ action, rider_id: riderId, city, duration, reason, result: res });
      return res || { ok: false, error: 'no_result', submitted: false };
    } finally {
      try { await page.close(); } catch (e) {}
    }
  } finally {
    busy = false;
  }
});

app.whenReady().then(() => {
  createWindow();
  if (app.isPackaged) {
    try {
      autoUpdater.on('error', () => {}); // no update feed until CI publishing lands
      autoUpdater.checkForUpdatesAndNotify().catch(() => {});
    } catch (e) {}
  }
});

app.on('window-all-closed', () => { app.quit(); });
