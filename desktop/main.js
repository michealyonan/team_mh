// team_mh Desktop - Electron main process.
// One window loads the whole team_mh site. A background agent polls the existing
// form queue (phone-poll/phone-report) and runs the form walker in a hidden window
// whose persistent partition holds Micheal's own Google session (his IP, real Chromium).
const { app, BrowserWindow, shell, session, Notification } = require('electron');
const { autoUpdater } = require('electron-updater');
const { buildWalkerScript } = require('./walker');

const SITE = 'https://team-mh.michealuonanayad.workers.dev';
const POLL_MS = 20000;
const WATCHDOG_MS = 90000;
const SIGNIN_WAIT_MS = 6 * 60 * 1000;

let mainWin = null;
let busy = false;

function createWindow() {
  mainWin = new BrowserWindow({
    width: 1320,
    height: 900,
    autoHideMenuBar: true,
    icon: __dirname + '/icon.png',
    webPreferences: { contextIsolation: true, sandbox: true }
  });
  mainWin.loadURL(SITE);
  mainWin.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });
}

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
