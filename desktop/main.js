// team_mh Desktop v0.3.0 - Electron main process.
// The window loads the team_mh site. مد الشيفت / فك البريك run DIRECTLY on this
// machine: a button tap drives the installed Chrome (persistent per-group profile,
// like Micheal's Python tool) - no server queue, no polling. Result shows as a local
// notification + in the dialog; a best-effort log line is posted to the site.
const { app, BrowserWindow, shell, Notification, ipcMain, clipboard } = require('electron');
const fs = require('fs');
const path = require('path');
const { autoUpdater } = require('electron-updater');
const { getBrowser, firstPage, peekBrowser, launchPlain, launchPlainForSignin, adoptBrowser, dropBrowser } = require('./chromeproc');
const { runFormWalk, clickX, pageMarker, confirmState } = require('./chromewalk');

const VERSION = '0.3.18';
// Proof image for فتح شيفت uploads: Micheal's OWN fixed image when present
// (userData/proof.*, seeded from a bundled proof.* on first run), else the
// app-generated black PNG fallback (24 Nov).
const BLACK_PNG_B64 = 'iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAIAAAAlC+aJAAAAIklEQVR4nO3BAQ0AAADCoPdPbQ8HFAAAAAAAAAAAAAAA8G4wQAABiwCo9wAAAABJRU5ErkJggg==';
const PROOF_NAMES = ['proof.png', 'proof.jpg', 'proof.jpeg', 'proof.webp'];
function seedBundledProof() {
  try {
    const ud = app.getPath('userData');
    if (PROOF_NAMES.some((n) => fs.existsSync(path.join(ud, n)))) return;
    const res = process.resourcesPath ? path.join(process.resourcesPath) : null;
    const candidates = [];
    if (res) { candidates.push(path.join(res, 'proof.png'), path.join(res, 'proof.jpg'), path.join(res, 'proof.jpeg'), path.join(res, 'proof.webp')); }
    candidates.push(path.join(__dirname, 'proof.png'), path.join(__dirname, 'proof.jpg'));
    for (const c of candidates) {
      if (fs.existsSync(c)) { fs.copyFileSync(c, path.join(ud, 'proof' + path.extname(c).toLowerCase())); return; }
    }
  } catch (e) {}
}
function proofPngPath() {
  const ud = app.getPath('userData');
  for (const n of PROOF_NAMES) {
    try { const p = path.join(ud, n); if (fs.existsSync(p) && fs.statSync(p).size > 100) return p; } catch (e) {}
  }
  const p = path.join(ud, 'tmh-proof-black.png');
  try { if (!fs.existsSync(p)) fs.writeFileSync(p, Buffer.from(BLACK_PNG_B64, 'base64')); } catch (e) {}
  return p;
}
const SITE = 'https://team-mh.michealuonanayad.workers.dev';
const FORMS = {
  alex: { url: 'https://docs.google.com/forms/u/0/d/e/1FAIpQLSffSwyTh0w4AYjTU9AG-kj-0UfJHcSTSYnR1DrWJ_h8iPYm3Q/viewform', email: 'alexlogistics.teammh101@gmail.com' },
  delta: { url: 'https://docs.google.com/forms/u/0/d/e/1FAIpQLSekxaUQPgiWq-Y_IPfsTx7wTANA324a2JklFJZ_Gxg9CGPaKA/viewform', email: 'deltalogistics.teammh1@gmail.com' }
};
const SIGNIN_WAIT_MS = 6 * 60 * 1000;
const WALK_WATCHDOG_MS = 150000;
const DEFAULT_SPACING_SEC = 10;
const MIN_SPACING_SEC = 10; // Micheal 24 Nov: HE controls the delay, floor 10s
// Response sheets Micheal shared (24 Nov): read-only status lookup via GViz JSON.
const SHEETS = {
  alex: '1x2kj37jcFZoBYSkzmqjvwWnhtAFECR9KuBTDySUs2jc',
  delta: '174wAXtlTcRtsAKZMNNOwkVOMoOR4EqxHtR7hRLHGpr8'
};

let mainWin = null;
let cmdWin = null;
let busy = false;
// The run currently in progress, for the ⛔ إيقاف button (24 Nov): abort()
// resolves the walk race immediately; the walk itself throws at its next
// checkpoint and can never reach إرسال after an abort.
let currentRun = null;
ipcMain.handle('tmh-copy-log', async () => {
  try {
    const p = path.join(app.getPath('userData'), 'tmh-last-run.log');
    clipboard.writeText(fs.readFileSync(p, 'utf8'));
    return { ok: true };
  } catch (e) { return { ok: false, error: 'no_log' }; }
});
ipcMain.handle('tmh-save-log', async () => {
  try {
    const srcP = path.join(app.getPath('userData'), 'tmh-last-run.log');
    const dst = path.join(app.getPath('desktop'), 'team_mh-log-' + Date.now() + '.txt');
    fs.copyFileSync(srcP, dst);
    return { ok: true, path: dst };
  } catch (e) { return { ok: false }; }
});
ipcMain.handle('tmh-stop-run', async () => {
  if (!currentRun) return { ok: false, state: 'idle' };
  if (currentRun.submitClicked) return { ok: false, state: 'submitted_uncertain' };
  currentRun.aborted = true;
  if (currentRun.abort) currentRun.abort();
  return { ok: true, state: 'aborting' };
});
let lastRunAt = 0;
const warmPages = {}; // per-group warm form tab: stays open between runs (Micheal 24 Nov: speed, like the pyw)

function historyPath() { return path.join(app.getPath('userData'), 'tmh-history.json'); }
function readHistory() {
  try { const r = JSON.parse(fs.readFileSync(historyPath(), 'utf8')); return Array.isArray(r) ? r : []; }
  catch (e) { return []; }
}
function appendHistory(row) {
  try {
    const h = readHistory();
    h.push(row);
    while (h.length > 300) h.shift();
    fs.writeFileSync(historyPath(), JSON.stringify(h));
  } catch (e) {}
}

function statePath() { return path.join(app.getPath('userData'), 'google-signin-state.json'); }
function readState() {
  try { return JSON.parse(fs.readFileSync(statePath(), 'utf8')); } catch (e) { return {}; }
}
function writeState(s) {
  try { fs.writeFileSync(statePath(), JSON.stringify(s)); } catch (e) {}
}
// User settings (delay between requests), saved on disk.
function settingsPath() { return path.join(app.getPath('userData'), 'tmh-settings.json'); }
function readSettings() {
  let s = {};
  try { s = JSON.parse(fs.readFileSync(settingsPath(), 'utf8')); } catch (e) {}
  let sec = parseInt(s.spacingSec, 10);
  if (!isFinite(sec) || sec < MIN_SPACING_SEC) sec = DEFAULT_SPACING_SEC;
  return { spacingSec: sec };
}
function writeSettings(s) {
  try { fs.writeFileSync(settingsPath(), JSON.stringify(s)); } catch (e) {}
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
  mainWin.webContents.on('did-navigate-in-page', () => { injectPanel(); });
}

// Collapsible floating panel (Micheal 24 Nov: one small ⚡ tab; panel opens on tap and
// closes after). Desktop-only; the website itself is unchanged. Only shown while a
// site session exists; hidden on the login screen (Micheal 24 Nov).
function injectPanel() {
  injectPanelDom();
}

function injectPanelDom() {
  const js = `
(function(){
  if (window.__tmhPanel || !window.tmhDesktop) return;
  window.__tmhPanel = 1;
  var tab = document.createElement('button');
  tab.id = 'tmh-tab';
  tab.textContent = '⚡';
  tab.title = 'team_mh';
  tab.style.cssText = 'position:fixed;bottom:16px;inset-inline-start:16px;z-index:99998;width:46px;height:46px;border-radius:50%;background:#16a34a;color:#fff;border:0;font-size:22px;cursor:pointer;box-shadow:0 6px 18px #0008;display:none';
  var box = document.createElement('div');
  box.id = 'tmh-panel';
  box.style.cssText = 'position:fixed;bottom:74px;inset-inline-start:16px;z-index:99999;background:#0f172a;border:1px solid #334155;border-radius:14px;padding:12px;color:#e2e8f0;font-family:Cairo,system-ui,sans-serif;font-size:13px;box-shadow:0 8px 24px #0009;min-width:210px;display:none';
  box.innerHTML = '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">'
    + '<div style="font-weight:800">⚡ team_mh</div>'
    + '<button data-tmh-close="1" style="background:none;border:0;color:#94a3b8;font-size:16px;cursor:pointer">✕</button></div>'
    + '<button data-tmh-cmd="1" style="width:100%;background:#16a34a;color:#fff;border:0;border-radius:10px;padding:10px;font:inherit;font-weight:900;cursor:pointer">⚡ مد الشيفت / فك البريك</button>'
    + '<div style="font-size:10px;color:#475569;margin-top:6px">v${VERSION} - دخول جوجل بيتم لوحده أول مرة في نافذة كروم</div>';
  document.body.appendChild(tab);
  document.body.appendChild(box);
  // Show ⚡ only when actually logged in: the site's own authToken() is truthy and the
  // login overlay (#lg) is hidden. Checked on an interval because login/logout happen
  // in-page (SPA, no navigation event). v0.3.11
  function tmhSync(){
    var tok = '';
    try { tok = (typeof window.authToken === 'function') ? window.authToken() : ''; } catch(e) {}
    var lg = document.getElementById('lg');
    var lgVisible = lg && getComputedStyle(lg).display !== 'none';
    var show = !!tok && !lgVisible;
    tab.style.display = show ? '' : 'none';
    if (!show) box.style.display = 'none';
  }
  tmhSync();
  setInterval(tmhSync, 1200);
  tab.addEventListener('click', function(){
    box.style.display = box.style.display === 'none' ? '' : 'none';
  });
  box.addEventListener('click', function(ev){
    if (ev.target.closest('[data-tmh-close]')) { box.style.display = 'none'; return; }
    if (ev.target.closest('button[data-tmh-cmd]')) { window.tmhDesktop.openCommands(); box.style.display = 'none'; }
  });
})();`;
  try { mainWin.webContents.executeJavaScript(js); } catch (e) {}
}

// Google sign-in per group, inside that group's dedicated real-Chrome profile.
async function openGoogleSignin(which) {
  const cfg = FORMS[which];
  if (!cfg) return;
  try { const b = peekBrowser(which); if (b) await b.close(); } catch (e) {}
  delete warmPages[which];
  let signed = null;
  try { signed = await manualSignin(which, cfg); } catch (e) { notify('team_mh ❌', 'مش قادر أفتح كروم على الجهاز ده'); return; }
  // Verify the session by attaching normally now (or reuse the signed page).
  try {
    const browser = signed && signed.browser ? signed.browser : await getBrowser(which, app.getPath('userData'));
    const page = signed && signed.page ? signed.page : await firstPage(browser);
    if (!signed) await page.goto(cfg.url, { waitUntil: 'domcontentloaded', timeout: 60000 });
    const url = await settleUrl(page, 15000);
    if (/docs\.google\.com\/forms/.test(url)) {
      let acct = '';
      try { acct = String(await page.evaluate(accountFromPageFn) || '').toLowerCase(); } catch (e) {}
      const st = readState();
      st[which] = { account: acct || cfg.email, at: Date.now() };
      writeState(st);
      pushState();
      notify('team_mh ✅', 'تم تسجيل الدخول: ' + (acct || cfg.email));
      warmPages[which] = page;
      return;
    }
  } catch (e) {}
  notify('team_mh ❌', 'تسجيل الدخول مكملش - جرّب تاني');
}

// Wait for the page URL to settle: Google Forms bounces through a client-side
// redirect to accounts.google.com when the profile is signed out, and judging the
// page on the first URL raced that redirect (the v0.3.0 about:blank bug).
async function settleUrl(page, ms) {
  const deadline = Date.now() + ms;
  let last = '';
  let stable = 0;
  while (Date.now() < deadline) {
    let url = '';
    try { url = page.url(); } catch (e) { return ''; }
    if (url === last) stable++; else { stable = 0; last = url; }
    if (stable >= 3 && url && url !== 'about:blank') return url;
    await sleep(500);
  }
  return last;
}

// First-time Google sign-in must happen in PLAIN Chrome (no automation flags):
// Google rejects sign-in inside the puppeteer-driven window ("This browser or
// app may not be secure"). We close the driven window, open normal Chrome on the
// form URL, and wait for Micheal to sign in and close the window himself.
async function manualSignin(group, cfg) {
  notify('team_mh 🔐', 'سجّل دخول جوجل بالحساب ' + cfg.email + ' في نافذة كروم اللي فتحت - أول ما صفحة الفورم تظهر التطبيق هيكمل لوحده');
  const signed = await launchPlainForSignin(group, app.getPath('userData'), cfg.url, SIGNIN_WAIT_MS);
  if (signed && signed.page) { adoptBrowser(group, signed.browser); return signed; }
  return null;
}

// Wait until the form page actually rendered its controls (post sign-in redirect).
async function waitFormReady(page, ms) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    try {
      const ready = await page.evaluate(() => !!document.querySelector("div[role='checkbox'], input[type='text'], div[role='listbox']"));
      if (ready) return true;
    } catch (e) {}
    await sleep(700);
  }
  return false;
}

function accountFromPageFn() {
  const m = document.documentElement.innerHTML.match(/([a-zA-Z0-9._%+-]+@(?!google\.com)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  return m ? m[1] : '';
}

// Warm-page reuse: if the group's form tab is still open, get a fresh page 0 from
// it instead of reloading the form from scratch (the slow part Micheal flagged).
// After a success the tab sits on the confirmation page - click "إرسال رد آخر /
// Submit another response" to reset. Mid-form (died earlier) -> reload the form.
async function preparePage(browser, group, formUrl) {
  let page = warmPages[group] || null;
  if (page) {
    try { await page.url(); } catch (e) { page = null; }
  }
  if (!page) {
    page = await firstPage(browser);
    try {
      await page.goto(formUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
    } catch (e) {
      // Dead/stuck tab: drop it and retry once on a brand-new tab (24 Nov).
      try { await page.close(); } catch (e2) {}
      page = await browser.newPage();
      await page.goto(formUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
    }
    return { page, cold: true };
  }
  const url = page.url();
  if (!/docs\.google\.com\/forms/.test(url)) {
    await page.goto(formUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
    return { page, cold: true };
  }
  // Confirmation page -> fresh copy via the "another response" link.
  try {
    const hasAnother = await page.evaluate(() => /إرسال رد آخر|Submit another/.test((document.body && document.body.innerText) || ''));
    if (hasAnother) {
      const before = await pageMarker(page);
      await clickX(page, "//a[contains(., 'إرسال رد آخر') or contains(., 'Submit another')]", 5000);
      const t0 = Date.now();
      while (Date.now() - t0 < 8000) {
        await sleep(120);
        // The click navigates the tab; mid-navigation reads throw "detached
        // Frame" (24 Nov Micheal). Keep polling until the new page settles.
        let m = '';
        try { m = await pageMarker(page); } catch (e) { continue; }
        if (m === '0' || (m && m !== before)) break;
      }
      return { page, cold: false };
    }
  } catch (e) {}
  // Already a fresh page 0 -> reuse as-is; anything else -> reload.
  try {
    if ((await pageMarker(page)) === '0') return { page, cold: false };
  } catch (e) {}
  await page.goto(formUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
  return { page, cold: true };
}

// ---- Response-sheet status (Micheal 24 Nov): read-only, via the group's own
// signed-in Chrome using the GViz JSON endpoint. Needs the sheet shared (viewer)
// with the form account; no API key, nothing written.
const sheetTabs = {};
async function fetchSheetRows(group) {
  const sheetId = SHEETS[group];
  if (!sheetId) return { ok: false, error: 'no_sheet' };
  // Polls reuse the ALREADY-OPEN group Chrome only; they must never launch a
  // window by themselves (that was the stray about:blank window every ~45s).
  // And never open/steal a tab while a walk is running (24 Nov: a poll tab
  // popped about:blank over the فتح شيفت picker).
  if (busy) return { ok: false, error: 'busy' };
  const browser = peekBrowser(group);
  if (!browser) return { ok: false, error: 'browser_off' };
  let page = sheetTabs[group] || null;
  if (page) { try { await page.url(); } catch (e) { page = null; } }
  let fresh = false;
  if (!page) {
    try { page = await browser.newPage(); fresh = true; } catch (e) { return { ok: false, error: 'tab_failed' } };
    sheetTabs[group] = page;
  }
  try {
    const url = 'https://docs.google.com/spreadsheets/d/' + sheetId + '/gviz/tq?tqx=out:json&headers=1';
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    if (fresh) {
      // Don't leave the poll tab in front of the form tab Micheal is watching.
      const warm = warmPages[group];
      if (warm) { try { await warm.bringToFront(); } catch (e) {} }
    }
    const out = await page.evaluate(() => {
      const t = (document.body && document.body.innerText) || '';
      let data = null;
      const g = { visualization: { Query: { setResponse: (d) => { data = d; } } } };
      try { (new Function('google', t))(g); } catch (e) { return JSON.stringify({ error: 'not_json', head: t.slice(0, 150) }); }
      if (!data || !data.table) return JSON.stringify({ error: 'no_table', head: t.slice(0, 150) });
      return JSON.stringify({
        cols: (data.table.cols || []).map((c) => String(c.label || c.id || '')),
        rows: (data.table.rows || []).map((r) => (r.c || []).map((cell) => {
          if (!cell) return '';
          if (cell.f != null) return String(cell.f);
          if (cell.v == null) return '';
          return (cell.v instanceof Date) ? cell.v.toISOString() : String(cell.v);
        }))
      });
    });
    const parsed = JSON.parse(out);
    if (parsed.error) return { ok: false, error: parsed.error === 'not_json' ? 'no_access' : parsed.error, detail: parsed.head || '' };
    const cols = parsed.cols;
    const find = (...keys) => cols.findIndex((c) => keys.some((k) => c.indexOf(k) >= 0));
    const ciRider = find('كود', 'المندوب', 'ID');
    const ciStatus = find('حالة', 'قبول');
    const ciReason = find('سبب الرفض', 'الرفض');
    const ciAction = find('نوع الطلب', 'الطلب');
    const rows = parsed.rows.map((r) => ({
      ts: r[0] || '',
      rider: (ciRider >= 0 ? r[ciRider] : '').replace(/[^0-9]/g, ''),
      action: ciAction >= 0 ? r[ciAction] : '',
      status: ciStatus >= 0 ? r[ciStatus] : '',
      rejectReason: ciReason >= 0 ? r[ciReason] : ''
    })).filter((r) => r.rider);
    return { ok: true, rows, colDebug: cols.join(' | ').slice(0, 200) };
  } catch (e) {
    return { ok: false, error: 'fetch_failed', detail: String(e).slice(0, 150) };
  }
}

ipcMain.handle('tmh-history', () => readHistory());
ipcMain.handle('tmh-sheet-status', (_e, group) => fetchSheetRows(String(group)));

ipcMain.on('tmh-google-signin', (_e, which) => { openGoogleSignin(String(which)); });
ipcMain.handle('tmh-google-state', () => readState());
ipcMain.handle('tmh-get-settings', () => readSettings());
ipcMain.handle('tmh-set-spacing', (_e, sec) => {
  let n = parseInt(sec, 10);
  if (!isFinite(n) || n < MIN_SPACING_SEC) n = MIN_SPACING_SEC;
  if (n > 3600) n = 3600;
  writeSettings({ spacingSec: n });
  return { ok: true, spacingSec: n };
});

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
  const duration = String(p.duration || '').trim();
  let reason = String(p.reason || '').trim();
  const manualProof = !!p.manualProof;
  if (!['extend', 'break', 'open'].includes(action)) return { ok: false, error: 'bad_action' };
  if (!riderId) return { ok: false, error: 'bad_rider' };
  if (!city) return { ok: false, error: 'bad_city' };
  if (action === 'extend' && !duration) return { ok: false, error: 'bad_duration' };
  const isAlex = city === 'الإسكندرية';
  if (action === 'break' && isAlex && !reason) return { ok: false, error: 'bad_reason' };
  // فتح شيفت: Delta form only, needs the vehicle number; reason defaults to موجود في الزون.
  const vehicle = String(p.vehicle || '').trim();
  if (action === 'open') {
    if (isAlex) return { ok: false, error: 'open_not_alex' };
    if (!vehicle) return { ok: false, error: 'bad_vehicle' };
    if (!reason) reason = 'موجود في الزون';
  }
  const dur = action === 'open' ? {} : parseDuration(action, isAlex, duration);
  if (dur.error) return { ok: false, error: dur.error };
  // Zone = city everywhere (Micheal 24 Nov). المدينة on the Delta form is typed
  // exactly الغردقه (Micheal 24 Nov, screenshot); الغردقة only ever goes to the
  // Delta form, so no per-form branch is needed.
  const cityVal = city === 'الغردقة' ? 'الغردقه' : city;
  const label = (action === 'break' ? 'فك بريك' : action === 'open' ? 'فتح شيفت' : 'مد الشيفت') + ' - ' + riderId;

  if (busy) return { ok: false, error: 'busy' };
  busy = true;
  currentRun = { aborted: false, submitClicked: false, abort: null };
  const abortPromise = new Promise((res) => { currentRun.abort = () => res({ ok: false, error: 'aborted', submitted: false }); });
  let page = null;
  let keepTab = false;
  try {
    // Anti-burst spacing between runs - Micheal's setting, floor 10s.
    const spacingMs = readSettings().spacingSec * 1000;
    const waitMs = spacingMs - (Date.now() - lastRunAt);
    if (waitMs > 0) {
      progress('spacing', { seconds: Math.ceil(waitMs / 1000) });
      await sleep(waitMs);
    }
    lastRunAt = Date.now();

    const group = (isAlex && action !== 'open') ? 'alex' : 'delta';
    const cfg = FORMS[group];
    progress('launch', {});
    let browser;
    try { browser = await getBrowser(group, app.getPath('userData')); }
    catch (e) {
      notify('team_mh ❌', 'مش لاقي جوجل كروم على الجهاز - نزّله الأول');
      return { ok: false, error: 'chrome_not_found' };
    }
    const prepT0 = Date.now();
    let prep;
    try { prep = await preparePage(browser, group, cfg.url); }
    catch (e) {
      const msg = String(e && (e.message || e) || '');
      // Stale tab / dropped CDP connection (24 Nov Micheal's "detached Frame"):
      // drop everything and retry ONCE on a freshly attached browser+tab.
      if (/detached|Target closed|Session closed|Protocol error|Connection closed|Target crashed/i.test(msg)) {
        try { delete warmPages[group]; } catch (e2) {}
        try { await dropBrowser(group); } catch (e2) {}
        try { browser = await getBrowser(group, app.getPath('userData')); } catch (e2) {
          return { ok: false, error: 'tab_failed', detail: msg.slice(0, 200), submitted: false };
        }
        try { prep = await preparePage(browser, group, cfg.url); }
        catch (e2) { return { ok: false, error: 'tab_failed', detail: String(e2 && (e2.message || e2)).slice(0, 200), submitted: false }; }
      } else {
        return { ok: false, error: 'tab_failed', detail: msg.slice(0, 200), submitted: false };
      }
    }
    page = prep.page;
    // Close any stray about:blank tabs in this window (leftovers from sign-in or
    // a poll tab) so Micheal only ever sees the form tab (24 Nov).
    try {
      for (const p2 of await browser.pages()) {
        if (p2 === page) continue;
        try { const u2 = p2.url(); if (!u2 || u2 === 'about:blank') await p2.close(); } catch (e) {}
      }
    } catch (e) {}
    try {
      let url = await settleUrl(page, prep.cold ? 15000 : 3000);

      // Google asks for sign-in: the automated window gets rejected, so switch to
      // plain Chrome for a one-time manual login, then re-attach and continue.
      if (/accounts\.google\.com/.test(url)) {
        progress('signin_wait', { email: cfg.email });
        try { await browser.close(); } catch (e) {}
        delete warmPages[group];
        try { delete sheetTabs[group]; } catch (e) {}
        let signed = null;
        try { signed = await manualSignin(group, cfg); }
        catch (e) { return { ok: false, error: 'chrome_not_found', submitted: false }; }
        if (signed && signed.page) {
          browser = signed.browser;
          page = signed.page;
        } else {
          try { browser = await getBrowser(group, app.getPath('userData')); }
          catch (e) { return { ok: false, error: 'chrome_not_found', submitted: false }; }
          try { page = await firstPage(browser); }
          catch (e) { return { ok: false, error: 'tab_failed', detail: String(e).slice(0, 200), submitted: false }; }
          try { await page.goto(cfg.url, { waitUntil: 'domcontentloaded', timeout: 60000 }); } catch (e) {}
        }
        url = await settleUrl(page, 15000);
        if (/accounts\.google\.com/.test(url)) { return { ok: false, error: 'auth_expired', detail: 'google sign-in not completed', submitted: false }; }
      }

      // Wait for the form to render before judging anything about it.
      const ready = await waitFormReady(page, 30000);
      if (!ready) { keepTab = true; return { ok: false, error: 'form_not_ready', detail: String(url).slice(0, 200), submitted: false }; }

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
          keepTab = true;
          return { ok: false, error: 'wrong_account', detail: 'signed in as ' + acct + ', expected ' + cfg.email, submitted: false };
        }
      }

      progress('walking', {});
      const thisRun = currentRun;
      const job = Object.assign({ isAlex: isAlex && action !== 'open', isOpen: action === 'open', action, riderId, city, cityVal, reason, duration, vehicle, proofPath: action === 'open' ? proofPngPath() : '', manualProof: action === 'open' && manualProof, onManualWait: () => { try { progress('manual_proof', {}); } catch (e) {} }, isAborted: () => !!thisRun.aborted, onSubmitting: () => { thisRun.submitClicked = true; } }, dur);
      let res;
      try {
        res = await Promise.race([
          runFormWalk(page, job),
          abortPromise,
          // Manual proof mode needs minutes, not the 150s walk watchdog (24 Nov).
          sleep(job.manualProof ? 380000 : WALK_WATCHDOG_MS).then(() => ({ ok: false, error: 'watchdog_timeout', submitted: false }))
        ]);
      } catch (e) {
        res = currentRun && currentRun.aborted
          ? { ok: false, error: 'aborted', submitted: false }
          : { ok: false, error: (e && e.aborted) ? 'aborted' : 'walk_exception', detail: String(e && (e.detail || e.message) || '').slice(0, 700), submitted: false, diag: (e && e.diag) || null };
      }
      // Full run log: local file (نسخ/حفظ اللوج buttons) + diag rides the worker post.
      try {
        fs.writeFileSync(path.join(app.getPath('userData'), 'tmh-last-run.log'), JSON.stringify({
          version: VERSION, ts: new Date().toISOString(), action, riderId, city,
          ok: !!(res && res.ok), error: (res && res.error) || '', detail: (res && res.detail) || '',
          diag: (res && res.diag) || null
        }, null, 2));
      } catch (e) {}
      const prepMs = Date.now() - prepT0;
      // Last-line false-negative guard (also covers the watchdog race): if the
      // tab is on Google's confirmation screen, the response WAS recorded.
      if ((!res || !res.ok) && page) {
        try {
          const fin = await confirmState(page);
          if (fin.done) res = { ok: true, submitted: true, detail: 'confirmed-at-final-check (was: ' + ((res && res.error) || 'no_result') + ')' };
        } catch (e) {}
      }
      if (res) res.detail = 'prep ' + prepMs + 'ms' + (prep.cold ? ' (cold load)' : ' (warm tab)') + (res.detail ? ' | ' + res.detail : '');
      lastRunAt = Date.now();
      if (res && res.ok) notify('team_mh ✅', 'تم: ' + label);
      else if (res && res.error === 'aborted') notify('team_mh ⛔', 'اتوقف: ' + label);
      else if (res && res.uncertain) notify('team_mh ⚠️', 'مش متأكد: ' + label + ' - اتأكد من الشيت قبل ما تعيد الطلب');
      else notify('team_mh ❌', 'فشل: ' + label + ' (' + ((res && res.error) || 'unknown') + ')');
      appendHistory({
        ts: Date.now(), action, riderId, city, duration, reason, vehicle,
        ok: !!(res && res.ok), error: (res && res.error) || '', uncertain: !!(res && res.uncertain),
        submitted: !!(res && res.submitted), detail: (res && res.detail || '').slice(0, 400)
      });
      logDirect({ action, rider_id: riderId, city, duration, reason, vehicle, result: res });
      return res || { ok: false, error: 'no_result', submitted: false };
    } finally {
      // The tab ALWAYS stays open and warm for the next run (Micheal 24 Nov: speed).
      if (page) warmPages[group] = page;
    }
  } finally {
    const wasAborted = !!(currentRun && currentRun.aborted);
    busy = false;
    currentRun = null;
    // After a Stop, fully reset this group's Chrome so the next run launches
    // clean (no locked profile, no stuck picker tab, no stale connection).
    if (wasAborted) {
      try { delete warmPages[group]; } catch (e) {}
      try { delete sheetTabs[group]; } catch (e) {}
      const b = peekBrowser(group);
      if (b) { b.close().catch(() => {}); }
    }
  }
});

app.whenReady().then(() => {
  createWindow();
  seedBundledProof();
  if (app.isPackaged) {
    try {
      autoUpdater.on('error', () => {}); // no update feed until CI publishing lands
      autoUpdater.checkForUpdatesAndNotify().catch(() => {});
    } catch (e) {}
  }
});

app.on('window-all-closed', () => { app.quit(); });
