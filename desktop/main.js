// team_mh Desktop - Electron main process.
// One window loads the whole team_mh site. A background agent polls the existing
// form queue (phone-poll/phone-report) and runs the form walker in a hidden window
// whose persistent partition holds Micheal's own Google session (his IP, real Chromium).
const { app, BrowserWindow, shell, session, Notification, ipcMain } = require('electron');
const fs = require('fs');
const path = require('path');
const { autoUpdater } = require('electron-updater');
const { buildWalkerScript } = require('./walker');

const SITE = 'https://team-mh.michealuonanayad.workers.dev';
const FORMS = {
  alex: { url: 'https://docs.google.com/forms/u/0/d/e/1FAIpQLSffSwyTh0w4AYjTU9AG-kj-0UfJHcSTSYnR1DrWJ_h8iPYm3Q/viewform', partition: 'persist:walker-alex', email: 'alexlogistics.teammh101@gmail.com' },
  delta: { url: 'https://docs.google.com/forms/u/0/d/e/1FAIpQLSekxaUQPgiWq-Y_IPfsTx7wTANA324a2JklFJZ_Gxg9CGPaKA/viewform', partition: 'persist:walker-delta', email: 'deltalogistics.teammh1@gmail.com' }
};
const POLL_MS = 20000;
const WATCHDOG_MS = 90000;
const SIGNIN_WAIT_MS = 6 * 60 * 1000;

let mainWin = null;
let busy = false;
const signinWins = {};

function statePath() { return path.join(app.getPath('userData'), 'google-signin-state.json'); }
function readState() {
  try { return JSON.parse(fs.readFileSync(statePath(), 'utf8')); } catch (e) { return {}; }
}
function writeState(s) {
  try { fs.writeFileSync(statePath(), JSON.stringify(s)); } catch (e) {}
}
function pushState() {
  if (mainWin && !mainWin.isDestroyed()) {
    try { mainWin.webContents.send('tmh-google-state', readState()); } catch (e) {}
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

// Floating panel inside the app window (desktop-only; the website itself is unchanged):
// per-city Google sign-in buttons with live status.
function injectPanel() {
  const js = `
(function(){
  if (window.__tmhPanel || !window.tmhDesktop) return;
  window.__tmhPanel = 1;
  var box = document.createElement('div');
  box.style.cssText = 'position:fixed;bottom:14px;inset-inline-start:14px;z-index:99999;background:#0f172a;border:1px solid #334155;border-radius:14px;padding:10px 12px;color:#e2e8f0;font-family:Cairo,system-ui,sans-serif;font-size:13px;box-shadow:0 8px 24px #0009;min-width:230px';
  function row(which,label){
    return '<div style="display:flex;align-items:center;gap:8px;margin:4px 0">'
      + '<button data-tmh="' + which + '" style="flex:1;background:#1d4ed8;color:#fff;border:0;border-radius:10px;padding:8px 10px;font:inherit;font-weight:700;cursor:pointer">' + label + '</button>'
      + '<span data-tmh-st="' + which + '" style="font-size:11px;color:#94a3b8;max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">…</span></div>';
  }
  box.innerHTML = '<div style="font-weight:800;margin-bottom:4px">🔐 دخول جوجل للفورم</div>'
    + row('alex','تسجيل دخول (اسكندرية)')
    + row('delta','تسجيل دخول (باقي المحافظات)')
    + '<button data-tmh-cmd="1" style="width:100%;margin-top:8px;background:#16a34a;color:#fff;border:0;border-radius:10px;padding:10px;font:inherit;font-weight:900;cursor:pointer">⚡ مد الشيفت / فك البريك</button>';
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
  box.addEventListener('click', function(ev){
    var b = ev.target.closest('button[data-tmh]');
    if (b) window.tmhDesktop.signin(b.getAttribute('data-tmh'));
    if (ev.target.closest('button[data-tmh-cmd]')) window.tmhDesktop.openCommands();
  });
  window.tmhDesktop.getState().then(paint).catch(function(){});
  window.tmhDesktop.onState(paint);
})();`;
  try { mainWin.webContents.executeJavaScript(js); } catch (e) {}
}

// Opens a visible window on the form so Micheal signs in once per city group;
// the session persists in the partition and the account is shown in the panel.
async function openGoogleSignin(which) {
  const cfg = FORMS[which];
  if (!cfg) return;
  if (signinWins[which] && !signinWins[which].isDestroyed()) {
    signinWins[which].show(); signinWins[which].focus(); return;
  }
  const ses = session.fromPartition(cfg.partition);
  const win = new BrowserWindow({
    width: 1100,
    height: 820,
    icon: __dirname + '/icon.png',
    webPreferences: { session: ses, sandbox: true, contextIsolation: true }
  });
  signinWins[which] = win;
  win.on('closed', () => { delete signinWins[which]; });
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https:\/\/(docs|accounts|myaccount)\.google\.com\//.test(url)) return { action: 'allow' };
    shell.openExternal(url);
    return { action: 'deny' };
  });
  const check = async () => {
    if (win.isDestroyed()) return;
    const url = win.webContents.getURL();
    if (/docs\.google\.com\/forms/.test(url) && !/accounts\.google\.com/.test(url)) {
      let acct = '';
      try { acct = String(await win.webContents.executeJavaScript(accountFromPage(), true) || '').toLowerCase(); } catch (e) {}
      if (acct) {
        const st = readState();
        st[which] = { account: acct, at: Date.now() };
        writeState(st);
        pushState();
        notify('team_mh', 'تم تسجيل الدخول: ' + acct);
        return;
      }
    }
    setTimeout(check, 2000);
  };
  win.loadURL(cfg.url);
  setTimeout(check, 2500);
}

ipcMain.on('tmh-google-signin', (_e, which) => { openGoogleSignin(String(which)); });
ipcMain.handle('tmh-google-state', () => readState());

let cmdWin = null;
function openCommands() {
  if (cmdWin && !cmdWin.isDestroyed()) { cmdWin.show(); cmdWin.focus(); return; }
  cmdWin = new BrowserWindow({
    width: 440,
    height: 640,
    parent: mainWin,
    icon: __dirname + '/icon.png',
    autoHideMenuBar: true,
    webPreferences: { contextIsolation: true, sandbox: true, preload: __dirname + '/preload.js' }
  });
  cmdWin.on('closed', () => { cmdWin = null; });
  cmdWin.loadFile(__dirname + '/commands.html');
}
ipcMain.on('tmh-open-commands', () => { openCommands(); });

ipcMain.handle('tmh-enqueue', async (_e, payload) => {
  const p = payload || {};
  const body = {
    action: String(p.action || ''),
    rider_id: String(p.rider_id || ''),
    city: String(p.city || ''),
    zone: String(p.zone || ''),
    duration: String(p.duration || ''),
    reason: String(p.reason || ''),
    manual: true
  };
  return api('/api/forms/phone-enqueue', { method: 'POST', body });
});

async function getToken() {
  try {
    if (!mainWin || mainWin.isDestroyed()) return '';
    const t = await mainWin.webContents.executeJavaScript(
      "(sessionStorage.getItem('pd_token')||localStorage.getItem('pd_remember_login')||'')");
    return typeof t === 'string' ? t : '';
  } catch (e) { return ''; }
}

async function api(path, opts) {
  const t = await getToken();
  const headers = { 'Content-Type': 'application/json' };
  if (t) headers.Authorization = 'Bearer ' + t;
  const r = await fetch(SITE + path, {
    method: (opts && opts.method) || 'GET',
    headers,
    body: opts && opts.body ? JSON.stringify(opts.body) : undefined
  });
  const d = await r.json().catch(() => null);
  if (!r.ok) { const e = new Error((d && d.error) || ('HTTP ' + r.status)); e.status = r.status; throw e; }
  return d;
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

function notify(title, body) {
  try { new Notification({ title, body }).show(); } catch (e) {}
}

async function waitForFormUrl(win) {
  const deadline = Date.now() + SIGNIN_WAIT_MS;
  while (Date.now() < deadline) {
    if (win.isDestroyed()) return null;
    const url = win.webContents.getURL();
    if (/docs\.google\.com\/forms/.test(url)) return url;
    await sleep(2000);
  }
  return null;
}

function accountFromPage() {
  return "(function(){var m=document.documentElement.innerHTML.match(/([a-zA-Z0-9._%+-]+@(?!google\\.com)[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})/);return m?m[1]:''})()";
}

async function runWalker(job) {
  // One persistent partition per form account: Alex vs the Delta cities.
  const partition = job.isAlex ? 'persist:walker-alex' : 'persist:walker-delta';
  const ses = session.fromPartition(partition);
  const expected = (job.email || '').toLowerCase();
  const win = new BrowserWindow({
    show: false,
    width: 1100,
    height: 800,
    webPreferences: { session: ses, sandbox: true, contextIsolation: true }
  });
  // Keep the walker inside Google domains; anything else opens externally.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https:\/\/(docs|accounts)\.google\.com\//.test(url)) return { action: 'allow' };
    shell.openExternal(url);
    return { action: 'deny' };
  });
  try {
    await win.loadURL(job.url);
    for (let signinRound = 0; signinRound < 2; signinRound++) {
      let url = win.webContents.getURL();
      if (/accounts\.google\.com/.test(url)) {
        // One-time Google sign-in inside the app; the partition keeps it afterwards.
        win.show();
        win.focus();
        win.flashFrame(true);
        notify('team_mh', 'سجّل دخول جوجل بالحساب ' + (job.email || '') + ' مرة واحدة في النافذة اللي ظهرت - والتطبيق هيكمل لوحده');
        url = await waitForFormUrl(win);
        win.flashFrame(false);
        if (!url) { win.hide(); return { ok: false, error: 'auth_expired', detail: 'google sign-in not completed in time', submitted: false }; }
      }
      // Verify the signed-in account matches this form's account (Micheal 24 Nov:
      // alexlogistics for Alexandria, deltalogistics for the other cities).
      let acct = '';
      try { acct = String(await win.webContents.executeJavaScript(accountFromPage(), true) || '').toLowerCase(); } catch (e) {}
      if (acct) {
        const st = readState();
        st[job.isAlex ? 'alex' : 'delta'] = { account: acct, at: Date.now() };
        writeState(st);
        pushState();
      }
      if (!expected || !acct || acct === expected) {
        // Run the walk.
        const script = buildWalkerScript(job);
        const exec = win.webContents.executeJavaScript(script, true);
        const res = await Promise.race([
          exec,
          sleep(WATCHDOG_MS).then(async () => {
            let diag = '';
            try { diag = win.webContents.getURL() + ' | t:' + (await win.webContents.executeJavaScript('document.title')); } catch (e) {}
            return { ok: false, error: 'watchdog_timeout', detail: diag.slice(0, 300), submitted: false };
          })
        ]);
        return res || { ok: false, error: 'no_result', submitted: false };
      }
      // Wrong account in this partition: clear it and ask for the right one once.
      if (signinRound === 0) {
        try { await ses.clearStorageData(); } catch (e) {}
        notify('team_mh', 'الحساب المسجل (' + acct + ') مش حساب الفورم. سجّل دخول بالحساب ' + (job.email || ''));
        await win.loadURL(job.url).catch(() => {});
        continue;
      }
      return { ok: false, error: 'wrong_account', detail: 'signed in as ' + acct + ', expected ' + expected, submitted: false };
    }
    return { ok: false, error: 'wrong_account', detail: 'sign-in loop', submitted: false };
  } finally {
    try { win.destroy(); } catch (e) {}
  }
}

async function agentTick() {
  if (busy) return;
  let d;
  try { d = await api('/api/forms/phone-poll'); } catch (e) { return; } // 401 until Micheal logs in; retry next tick
  if (!(d && d.job)) return;
  busy = true;
  try {
    const res = await runWalker(d.job);
    await api('/api/forms/phone-report', { method: 'POST', body: Object.assign({ id: d.job.id }, res) });
    const label = (d.job.action === 'break' ? 'فك بريك' : 'مد الشيفت') + ' - ' + (d.job.riderId || '');
    if (res && res.ok) notify('team_mh ✅', 'تم: ' + label);
    else notify('team_mh ❌', 'فشل: ' + label + ' (' + ((res && res.error) || 'unknown') + ')');
  } catch (e2) {
    try {
      await api('/api/forms/phone-report', { method: 'POST', body: { id: d.job.id, ok: false, error: 'agent_exception', detail: String(e2).slice(0, 300), submitted: false } });
    } catch (e3) {}
  }
  busy = false;
}

app.whenReady().then(() => {
  createWindow();
  setInterval(agentTick, POLL_MS);
  if (app.isPackaged) {
    try {
      autoUpdater.on('error', () => {}); // no update feed until CI publishing lands
      autoUpdater.checkForUpdatesAndNotify().catch(() => {});
    } catch (e) {}
  }
});

app.on('window-all-closed', () => { app.quit(); });
