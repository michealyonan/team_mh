// team_mh desktop v0.3.0 - real-Chrome process manager.
// Launches the INSTALLED chrome.exe with a dedicated persistent profile per account
// group (alex / delta) inside the app's own data folder. Micheal's normal Chrome
// profile is never touched. Browsers stay open between runs so repeat taps are fast
// and the Google sign-in persists via the profile dir.
const fs = require('fs');
const path = require('path');
const puppeteer = require('puppeteer-core');
const { spawn } = require('child_process');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function chromeCandidates() {
  const list = [];
  const roots = [process.env['PROGRAMFILES'], process.env['PROGRAMFILES(X86)'], process.env['LOCALAPPDATA']];
  for (const r of roots) { if (r) list.push(path.join(r, 'Google', 'Chrome', 'Application', 'chrome.exe')); }
  list.push('C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe');
  list.push('C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe');
  return list;
}

function findChrome() {
  for (const p of chromeCandidates()) {
    try { if (p && fs.existsSync(p)) return p; } catch (e) {}
  }
  return '';
}

const browsers = {}; // group -> Browser

function browserAlive(b) {
  try { return !!(b && (typeof b.connected === 'boolean' ? b.connected : b.isConnected())); } catch (e) { return false; }
}

// Reuse Chrome's initial tab instead of opening a second one: what Micheal sees
// navigate is the tab Chrome opened with, never a leftover about:blank.
async function firstPage(browser) {
  try {
    const pages = await browser.pages();
    if (pages && pages.length) {
      // Prefer an already-loaded tab over a leftover about:blank (24 Nov).
      for (const p of pages) { try { const u = p.url(); if (u && u !== 'about:blank') return p; } catch (e) {} }
      return pages[0];
    }
  } catch (e) {}
  return browser.newPage();
}

async function getBrowser(group, userDataRoot) {
  if (browserAlive(browsers[group])) return browsers[group];
  delete browsers[group];
  const exe = findChrome();
  if (!exe) { const e = new Error('chrome_not_found'); e.code = 'chrome_not_found'; throw e; }
  const userDataDir = path.join(userDataRoot, 'chrome-profiles', group);
  try { fs.mkdirSync(userDataDir, { recursive: true }); } catch (e) {}
  const browser = await puppeteer.launch({
    executablePath: exe,
    userDataDir,
    headless: false,
    defaultViewport: null,
    // Match the Selenium tool: no --enable-automation (removes the automation
    // infobar AND navigator.webdriver=true, which Google fingerprints).
    ignoreDefaultArgs: ['--enable-automation'],
    args: [
      '--start-maximized',
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-session-crashed-bubble',
      '--hide-crash-restore-bubble',
      '--disable-features=ChromeWhatsNewUI'
    ]
  });
  try { browser.on('disconnected', () => { delete browsers[group]; }); } catch (e) {}
  browsers[group] = browser;
  return browser;
}

// PLAIN Chrome launch for first-time Google sign-in: no puppeteer attach, no
// remote debugging, no automation fingerprint - Google's sign-in page rejects
// automated browsers ("This browser or app may not be secure", 24 Nov delta).
// He signs in manually in a completely normal Chrome; cookies persist in the
// group profile dir; the next run attaches and works.
function launchPlain(group, userDataRoot, url) {
  const exe = findChrome();
  if (!exe) { const e = new Error('chrome_not_found'); e.code = 'chrome_not_found'; throw e; }
  const userDataDir = path.join(userDataRoot, 'chrome-profiles', group);
  try { fs.mkdirSync(userDataDir, { recursive: true }); } catch (e) {}
  // --remote-debugging-port=0: normal Chrome (no --enable-automation, webdriver
  // stays false) that we can still attach to via the DevToolsActivePort file -
  // so the app sees sign-in complete WITHOUT Micheal having to close the window.
  const child = spawn(exe, [
    '--user-data-dir=' + userDataDir,
    '--remote-debugging-port=0',
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-session-crashed-bubble',
    '--hide-crash-restore-bubble',
    '--start-maximized',
    url
  ], { stdio: 'ignore' });
  return { child, userDataDir };
}

// Watch a plain-Chrome sign-in: attach via DevToolsActivePort and wait until a
// tab reaches the form (signed in). Resolves {browser, page} to CONTINUE on the
// same window, or null on close/timeout (caller re-attaches fresh).
async function launchPlainForSignin(group, userDataRoot, url, timeoutMs) {
  const { child, userDataDir } = launchPlain(group, userDataRoot, url);
  const portFile = path.join(userDataDir, 'DevToolsActivePort');
  const t0 = Date.now();
  let browser = null;
  while (Date.now() - t0 < (timeoutMs || 360000)) {
    if (!browser) {
      try {
        const first = fs.readFileSync(portFile, 'utf8').split(/\r?\n/)[0].trim();
        if (first) browser = await puppeteer.connect({ browserURL: 'http://127.0.0.1:' + first });
      } catch (e) {}
    } else {
      try {
        const pages = await browser.pages();
        for (const p of pages) {
          const u = p.url();
          if (/docs\.google\.com\/forms/.test(u) && !/accounts\.google\.com/.test(u)) {
            return { browser, page: p };
          }
        }
      } catch (e) { browser = null; }
    }
    if (child.exitCode !== null) break; // window closed
    await sleep(2000);
  }
  if (browser) { try { browser.disconnect(); } catch (e) {} }
  return null;
}

function adoptBrowser(group, browser) { browsers[group] = browser; }

// Non-launching peek: returns the cached browser ONLY if already connected.
// Pollers (sheet status) must never relaunch Chrome by themselves - a poll that
// relaunches is what popped stray about:blank windows every ~45s (24 Nov).
function peekBrowser(group) {
  return browserAlive(browsers[group]) ? browsers[group] : null;
}

module.exports = { getBrowser, findChrome, firstPage, peekBrowser, launchPlain, launchPlainForSignin, adoptBrowser };
