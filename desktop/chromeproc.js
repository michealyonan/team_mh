// team_mh desktop v0.3.0 - real-Chrome process manager.
// Launches the INSTALLED chrome.exe with a dedicated persistent profile per account
// group (alex / delta) inside the app's own data folder. Micheal's normal Chrome
// profile is never touched. Browsers stay open between runs so repeat taps are fast
// and the Google sign-in persists via the profile dir.
const fs = require('fs');
const path = require('path');
const puppeteer = require('puppeteer-core');

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
    if (pages && pages.length) return pages[0];
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

module.exports = { getBrowser, findChrome, firstPage };
