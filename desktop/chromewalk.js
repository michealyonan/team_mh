// team_mh desktop v0.3.5 - Google Forms walk inside REAL Chrome (puppeteer-core).
// Node-side driver using TRUSTED input events (real mouse clicks / keyboard.type),
// the exact equivalent of Selenium's click()/send_keys() in Micheal's Python tool.
// v0.3.5: speed pass - event-based waits instead of fixed sleeps (page-advance is
// detected via the hidden pageHistory marker, options are awaited not slept on),
// and per-step timings in every result so we can see where the time goes.
//
// Step order mirrors process_request / process_request_alex / select_time_option_smart.

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const path = require('path');
const fs = require('fs');

const NEXT_X = "//span[contains(text(), 'التالي') or contains(text(), 'Next')]";
const SUBMIT_X = "//span[contains(text(), 'إرسال') or contains(text(), 'Submit')]";
const ANOTHER_X = "//a[contains(., 'إرسال رد آخر') or contains(., 'Submit another')]";

async function xpAll(page, x) {
  try { return await page.$$('xpath/' + x); } catch (e) { return []; }
}

// Trusted-click the first VISIBLE match, fresh handle every pass.
async function clickX(page, x, timeoutMs) {
  const t0 = Date.now();
  let lastErr = null;
  while (Date.now() - t0 < (timeoutMs || 12000)) {
    const els = await xpAll(page, x);
    for (const el of els) {
      try {
        let box = await el.boundingBox();
        if (!box || box.width < 2 || box.height < 2) continue;
        await el.evaluate((n) => { try { n.scrollIntoView({ block: 'center' }); } catch (e) {} });
        await sleep(80);
        box = await el.boundingBox();
        if (!box) continue;
        await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
        await sleep(300); // Micheal 24 Nov: correct over fast - let the page react.
        return;
      } catch (e) { lastErr = e; }
    }
    await sleep(150);
  }
  const e = lastErr || new Error('timeout clicking ' + x.slice(0, 70));
  e.detail = 'click target: ' + x.slice(0, 90);
  throw e;
}

// Same as clickX but clicks the Nth VISIBLE match (0-based) - the hiring form has
// five identical 'إضافة ملف' upload buttons, one per image question (24 Nov).
async function clickXNth(page, x, nth, timeoutMs) {
  const t0 = Date.now();
  let lastErr = null;
  while (Date.now() - t0 < (timeoutMs || 12000)) {
    const els = await xpAll(page, x);
    let seen = 0;
    for (const el of els) {
      try {
        let box = await el.boundingBox();
        if (!box || box.width < 2 || box.height < 2) continue;
        if (seen++ !== nth) continue;
        await el.evaluate((n) => { try { n.scrollIntoView({ block: 'center' }); } catch (e) {} });
        await sleep(80);
        box = await el.boundingBox();
        if (!box) { seen--; continue; }
        await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
        await sleep(300);
        return;
      } catch (e) { lastErr = e; }
    }
    await sleep(150);
  }
  const e = lastErr || new Error('timeout clicking nth(' + nth + ') ' + x.slice(0, 70));
  e.detail = 'click target nth ' + nth + ': ' + x.slice(0, 90);
  throw e;
}

// Trusted click on a specific element handle: real mouse event at its center.
async function clickEl(page, el) {
  await el.evaluate((n) => { try { n.scrollIntoView({ block: 'center' }); } catch (e) {} });
  await sleep(80);
  const box = await el.boundingBox();
  if (!box) throw new Error('element not visible');
  await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
  await sleep(250); // settle after every click (24 Nov)
}
// Trusted typing into a specific handle: mouse-click it, then real keys.
async function typeIn(page, el, text) {
  await clickEl(page, el);
  await page.keyboard.type(String(text), { delay: 45 }); // human-ish cadence (24 Nov)
  await sleep(250);
}

// Pick a form OPTION by text: strictly prefer role-scoped matches (radio/option)
// so a section header carrying the same words can never swallow the click.
async function pickOption(page, text, timeoutMs) {
  // Live DOM (24 Nov): the option label span sits in a div[role=radiogroup], the
  // clickable div[role=radio] is its sibling - click the radio in the group whose
  // label matches, so a section header carrying the same words can't swallow it.
  const scoped = "//div[@role='radiogroup'][.//span[contains(text(), '" + text + "')]]//div[@role='radio'] | //div[@role='option'][.//span[contains(text(), '" + text + "')]]";
  try {
    await clickX(page, scoped, Math.min(timeoutMs || 12000, 9000));
    return;
  } catch (e) {}
  // Delta DOM variant: the radio itself carries the label in aria-label.
  try {
    await clickX(page, "//div[@role='radio'][contains(@aria-label, '" + text + "')] | //div[@role='option'][contains(@aria-label, '" + text + "')]", 5000);
    return;
  } catch (e) {}
  // Last resort: the visible label element itself (Google rows select on label click).
  await clickX(page, "//*[self::span or self::div][normalize-space(text())='" + text + "' and not(div)]", 8000);
}

// Marker for the currently rendered page: the hidden pageHistory input value.
async function pageMarker(page) {
  try {
    return await page.evaluate(() => {
      const el = document.querySelector('input[name="pageHistory"]');
      return el ? String(el.value) : '';
    });
  } catch (e) { return ''; }
}

// Click Next and wait for the page to ACTUALLY advance (event-based, fast);
// if Google bounced us back with a validation error, say which one.
async function clickNext(page, timeoutMs) {
  const before = await pageMarker(page);
  // Two attempts: a fast second click covers a Next pressed before a dropdown
  // selection committed (Google bounces validation but keeps the page painted).
  for (let attempt = 0; attempt < 2; attempt++) {
    await clickX(page, NEXT_X, attempt ? 8000 : (timeoutMs || 15000));
    const t0 = Date.now();
    const limit = attempt ? 5000 : 8000;
    while (Date.now() - t0 < limit) {
      await sleep(120);
      const after = await pageMarker(page);
      if (after && after !== before) return;
    }
  }
  const err = await page.evaluate(() => {
    // Precise error text only - the form legend ("تشير إلى أنّ السؤال مطلوب" /
    // "Indicates required question") must NOT count as a validation error.
    const m = document.body ? document.body.innerText.match(/[^\n]*(?:هذا السؤال مطلوب|this is a required question)[^\n]*/i) : null;
    return m ? m[0].slice(0, 120) : '';
  });
  const e = new Error('validation_blocked' + (err ? ': ' + err : ''));
  e.code = 'validation_blocked';
  throw e;
}

// Is the page on the post-submit confirmation? URL-first: Google navigates to
// /formResponse and shows "recorded" / "Submit another". Checked alone this is
// decisive even if an old validation message is still painted during "Saving...".
async function confirmState(page) {
  try {
    const state = await page.evaluate(() => {
      const t = (document.body && document.body.innerText) || '';
      return {
        recorded: /تم تسجيل ردك|response has been recorded|إرسال رد آخر|Submit another/i.test(t),
        required: /هذا السؤال مطلوب|this is a required question/i.test(t),
        text: t.slice(0, 400)
      };
    });
    // NOTE: the URL is /formResponse during normal filling on this form (draft
    // autosave, "Saving..."), so only the recorded/another-response TEXT is proof.
    if (state.recorded) return { done: true };
    return { done: false, required: state.required, text: state.text };
  } catch (e) { return { done: false }; }
}

// After إرسال: wait for the FINAL confirmation (recorded text or the /formResponse
// URL) for the full window before judging - Google keeps the old page (including
// any validation message) painted while it shows "Saving...", which v0.3.5 misread
// as a rejection on a submit that actually went through (Micheal 24 Nov).
async function waitConfirmation(page, timeoutMs) {
  const t0 = Date.now();
  let sawRequired = '';
  while (Date.now() - t0 < (timeoutMs || 15000)) {
    const s = await confirmState(page);
    if (s.done) return { ok: true, submitted: true };
    if (s.required && !sawRequired) sawRequired = s.text || '';
    await sleep(400);
  }
  // Never cried success; how sure are we it failed?
  if (sawRequired) return { ok: false, error: 'validation_blocked', submitted: false, detail: sawRequired.slice(0, 300) };
  return { ok: false, error: 'unconfirmed', uncertain: true, submitted: false, detail: 'no confirmation within ' + (timeoutMs || 15000) + 'ms' };
}

// Google Forms file upload (v0.3.13). The Docs picker is a cross-origin OOPIF
// that plain page.frames() AND per-target CDP both missed on the real Delta form
// (24 Nov). Now: browser-level FLAT attach (Target.attachToTarget flatten:true)
// exposes every frame target including the picker OOPIF; each session gets
// Page.setInterceptFileChooserDialog. Layers:
//  v0.3.26 layers (drag-drop REMOVED - a missed drop opened the file as a
//  Chrome tab, Micheal 25 Nov videos):
//  1) تصفّح click inside the visible picker + chooser interception (main page
//     session armed too - in-process iframes fire on the page target);
//  2) DOM.setFileInputFiles on the VISIBLE picker frame only (a stale closed
//     picker iframe swallows the set silently);
//  3) CDP session scan for a picker page.frames cannot see;
//  4) Windows: real click WITHOUT interception, then PowerShell types the path
//     into the native Open dialog (clipboard paste + Enter).
// Passes only when the file chip (its name) is visible back on the form;
// otherwise throws with a full diagnostic trace, and the walk never submits.
const { execFile } = require('child_process');

async function uploadProof(page, filePath, job) {
  const fileName = path.basename(filePath || '') || 'proof.png';
  const browser = page.browser();
  const diag = { targets: [], layers: [] };
  const aborted = () => { if (job && job.isAborted && job.isAborted()) { const ab = new Error('aborted'); ab.aborted = true; throw ab; } };

  let chooserAnswered = false;
  let browserSession = null;
  const childSessions = new Set();

  async function armSession(cs, label) {
    try {
      await cs.send('Page.enable').catch(() => {});
      await cs.send('Page.setInterceptFileChooserDialog', { enabled: true }).catch(() => {});
      cs.on('Page.fileChooserOpened', async (ev) => {
        // v0.3.27: answer ONCE. The same dialog reaches every armed session of
        // the page target, and a second setFileInputFiles mid-upload resets the
        // input - the upload restarts/aborts and the chip never appears
        // (25 Nov: slots 1-2 ok, slot 3 answered twice, no chip).
        if (chooserAnswered) { diag.layers.push('chooser re-fired - ignored'); return; }
        chooserAnswered = true;
        try {
          await cs.send('DOM.setFileInputFiles', { files: [filePath], backendNodeId: ev.backendNodeId });
          diag.layers.push('chooser answered via ' + label);
        } catch (e) { diag.layers.push('chooser answer failed: ' + String(e).slice(0, 80)); }
        try { await cs.send('Page.setInterceptFileChooserDialog', { enabled: false }); } catch (e) {}
      });
    } catch (e) {}
  }

  const safeUrl = (f) => { try { return f.url() || ''; } catch (e) { return ''; } };

  async function attachAll() {
    try {
      const { targetInfos } = await browserSession.send('Target.getTargets');
      for (const ti of targetInfos) {
        if (ti.type === 'browser') continue;
        if (ti.type === 'page') continue; // main page session is armed separately; a second armed session on it double-answers the chooser
        const key = ti.targetId;
        if (diag.targets.indexOf(ti.type + ':' + (ti.url || '').slice(0, 60)) < 0) {
          diag.targets.push(ti.type + ':' + (ti.url || '').slice(0, 60));
        }
        if (childSessions[key]) continue;
        try {
          const r = await browserSession.send('Target.attachToTarget', { targetId: ti.targetId, flatten: true });
          const cs = browserSession.connection().session(r.sessionId);
          if (cs) { childSessions[key] = cs; try { cs.__tmhUrl = ti.url || ''; } catch (e) {} childSessions.add(cs); await armSession(cs, ti.type); }
        } catch (e) {}
      }
    } catch (e) { diag.layers.push('attachAll: ' + String(e).slice(0, 80)); }
  }

  async function setViaSessions() {
    const sessions = [];
    for (const cs of childSessions) { if (cs && typeof cs.send === 'function') sessions.push(cs); }
    // Picker sessions first; NEVER the form page session (24 Nov: same trap as
    // the main frame - the form's hidden input swallows the file, picker stays
    // empty and the chip never appears).
    sessions.sort((a, b) => (/picker/i.test(a.__tmhUrl || '') ? 0 : 1) - (/picker/i.test(b.__tmhUrl || '') ? 0 : 1));
    for (const cs of sessions) {
      const su = cs.__tmhUrl || '';
      if (/docs\.google\.com\/forms/i.test(su)) continue;
      try {
        await cs.send('DOM.enable').catch(() => {});
        const doc = await cs.send('DOM.getDocument', { depth: -1, pierce: true });
        const q = await cs.send('DOM.querySelector', { nodeId: doc.root.nodeId, selector: "input[type='file']" });
        if (q && q.nodeId) {
          await cs.send('DOM.setFileInputFiles', { files: [filePath], nodeId: q.nodeId });
          diag.layers.push('file set via session ' + su.slice(0, 60));
          return true;
        }
      } catch (e) {}
    }
    return false;
  }

  // Viewport rect of the big picker iframe, read from the main page's DOM
  // (the iframe ELEMENT is visible even when its content is cross-origin).
  async function pickerRect() {
    try {
      return await page.evaluate(() => {
        let best = null;
        for (const f of Array.from(document.querySelectorAll('iframe'))) {
          const r = f.getBoundingClientRect();
          if (r.width > 250 && r.height > 250 && (!best || r.width * r.height > best.w * best.h)) {
            best = { x: r.x, y: r.y, w: r.width, h: r.height };
          }
        }
        return best;
      });
    } catch (e) { return null; }
  }

  async function pickerButtonPoint() {
    // Fastest exact path: puppeteer's frame tree (covers in-process iframes and
    // puppeteer-exposed OOPIFs). The iframe ELEMENT rect comes from the top page.
    const BTN_JS = "(function(){var bs=document.querySelectorAll('button,[role=button],div');for(var i=0;i<bs.length;i++){var t=(bs[i].textContent||'').trim();if(t.replace(/[\u064B-\u0652\u0640]/g,'').indexOf('تصفح')>=0||/browse/i.test(t)){var r=bs[i].getBoundingClientRect();if(r.width>10&&r.width<300&&r.height>10&&r.height<100)return JSON.stringify({x:r.x+r.width/2,y:r.y+r.height/2});}}return ''})()";
    for (const f of page.frames()) {
      if (f === page.mainFrame()) continue;
      try {
        const v = await f.evaluate(BTN_JS);
        if (v) {
          const inner = JSON.parse(v);
          const fu = f.url();
          const off = await page.evaluate((u) => {
            const ifs = Array.from(document.querySelectorAll('iframe'));
            for (const fr of ifs) { if (u && fr.src && u.indexOf(fr.src.slice(0, 60)) === 0) { const r = fr.getBoundingClientRect(); return { x: r.x, y: r.y }; } }
            const big = ifs.map((fr) => fr.getBoundingClientRect()).filter((r2) => r2.width > 250 && r2.height > 250);
            return big.length ? { x: big[0].x, y: big[0].y } : { x: 0, y: 0 };
          }, fu).catch(() => ({ x: 0, y: 0 }));
          diag.layers.push('button coords via frame');
          return { x: off.x + inner.x, y: off.y + inner.y };
        }
      } catch (e) {}
    }
    // Exact coords from a session whose document has the تصفّح button.
    for (const cs of childSessions) {
      if (typeof cs.send !== 'function') continue;
      try {
        const r = await cs.send('Runtime.evaluate', {
          expression: "(function(){var bs=document.querySelectorAll('button,[role=button],div');for(var i=0;i<bs.length;i++){var t=(bs[i].textContent||'').trim();if(t.replace(/[\u064B-\u0652\u0640]/g,'').indexOf('تصفح')>=0||/browse/i.test(t)){var r=bs[i].getBoundingClientRect();if(r.width>10&&r.width<300&&r.height>10&&r.height<100)return JSON.stringify({x:r.x+r.width/2,y:r.y+r.height/2});}}return ''})()",
          returnByValue: true
        });
        const v = r && r.result && r.result.value;
        if (v) {
          const inner = JSON.parse(v);
          const href = await cs.send('Runtime.evaluate', { expression: 'location.href', returnByValue: true }).catch(() => null);
          const frameUrl = href && href.result && href.result.value ? String(href.result.value) : '';
          const off = await page.evaluate((fu) => {
            const ifs = Array.from(document.querySelectorAll('iframe'));
            for (const f of ifs) { if (fu && f.src && fu.indexOf(f.src.slice(0, 60)) === 0) { const r = f.getBoundingClientRect(); return { x: r.x, y: r.y }; } }
            const big = ifs.map((f) => f.getBoundingClientRect()).filter((r2) => r2.width > 250 && r2.height > 250);
            return big.length ? { x: big[0].x, y: big[0].y } : { x: 0, y: 0 };
          }, frameUrl).catch(() => ({ x: 0, y: 0 }));
          diag.layers.push('button coords via session');
          return { x: off.x + inner.x, y: off.y + inner.y };
        }
      } catch (e) {}
    }
    // Proportional estimate inside the modal (button sits ~78% down, centered).
    const rect = await pickerRect();
    if (rect) { diag.layers.push('button coords estimated'); return { x: rect.x + rect.w * 0.44, y: rect.y + rect.h * 0.79 }; }
    return null;
  }

  async function chipVisible() {
    try { return await page.evaluate((fn) => ((document.body && document.body.innerText) || '').indexOf(fn) >= 0, fileName); } catch (e) { return false; }
  }

  async function waitChip(ms) {
    const t0 = Date.now();
    while (Date.now() - t0 < ms) {
      aborted();
      if (await chipVisible()) return true;
      await sleep(700);
    }
    return false;
  }

  async function osClickAndFill(opts) {
    // Windows only: one PowerShell script does everything at OS level - finds the
    // Chrome window by title, brings it to front, maps the CSS-viewport point to
    // physical screen pixels via Chrome_RenderWidgetHostHWND, performs a REAL
    // mouse click (SetCursorPos + mouse_event), waits for the native Open dialog
    // (#32770), pastes the file path from the clipboard and presses Enter.
    if (process.platform !== 'win32') return false;
    const ps1 = path.join(require('os').tmpdir(), 'tmh-osclick.ps1');
    const script = [
      'param([string]$TitleMatch,[double]$RelX,[double]$RelY,[double]$InnerW,[string]$FilePath)',
      'Add-Type -AssemblyName System.Windows.Forms',
      'Add-Type @"',
      'using System;using System.Runtime.InteropServices;using System.Text;',
      'public class U32 {',
      ' [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);',
      ' public delegate bool EnumProc(IntPtr h, IntPtr l);',
      ' [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);',
      ' [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);',
      ' [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);',
      ' [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);',
      ' [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr FindWindowEx(IntPtr p, IntPtr c, string cls, string title);',
      ' [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, out RECT r);',
      ' [DllImport("user32.dll")] public static extern bool ClientToScreen(IntPtr h, ref POINT p);',
      ' [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);',
      ' [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint dx, uint dy, uint d, IntPtr e);',
      ' public struct RECT { public int Left, Top, Right, Bottom; }',
      ' public struct POINT { public int X, Y; }',
      '}',
      '"@',
      '$main = [IntPtr]::Zero',
      '$cb = [U32+EnumProc]{ param($h,$l)',
      '  $cn = New-Object System.Text.StringBuilder 256; [void][U32]::GetClassName($h,$cn,256)',
      '  if ($cn.ToString() -eq "Chrome_WidgetWin_1" -and [U32]::IsWindowVisible($h)) {',
      '    $tt = New-Object System.Text.StringBuilder 512; [void][U32]::GetWindowText($h,$tt,512)',
      '    if ($tt.ToString() -match [regex]::Escape($TitleMatch)) { $script:main = $h; return $false }',
      '  }',
      '  return $true',
      '}',
      '[void][U32]::EnumWindows($cb,[IntPtr]::Zero)',
      'if ($main -eq [IntPtr]::Zero) { Write-Output "NO_WINDOW"; exit 1 }',
      '$wid = [U32]::FindWindowEx($main,[IntPtr]::Zero,"Chrome_RenderWidgetHostHWND",$null)',
      'if ($wid -eq [IntPtr]::Zero) { Write-Output "NO_WIDGET"; exit 1 }',
      '[void][U32]::SetForegroundWindow($main)',
      'Start-Sleep -Milliseconds 400',
      '$cr = New-Object U32+RECT',
      '[void][U32]::GetClientRect($wid,[ref]$cr)',
      '$scale = ($cr.Right - $cr.Left) / $InnerW',
      '$pt = New-Object U32+POINT',
      '$pt.X = [int]($RelX * $scale); $pt.Y = [int]($RelY * $scale)',
      '[void][U32]::ClientToScreen($wid,[ref]$pt)',
      '[void][U32]::SetCursorPos($pt.X,$pt.Y)',
      'Start-Sleep -Milliseconds 250',
      '[U32]::mouse_event(0x0002,0,0,0,[IntPtr]::Zero)',
      'Start-Sleep -Milliseconds 90',
      '[U32]::mouse_event(0x0004,0,0,0,[IntPtr]::Zero)',
      '$dlg = [IntPtr]::Zero',
      '$deadline = (Get-Date).AddSeconds(20)',
      'while ((Get-Date) -lt $deadline -and $dlg -eq [IntPtr]::Zero) {',
      '  $found = [IntPtr]::Zero',
      '  $cb2 = [U32+EnumProc]{ param($h,$l)',
      '    $cn = New-Object System.Text.StringBuilder 256; [void][U32]::GetClassName($h,$cn,256)',
      '    if ($cn.ToString() -eq "#32770" -and [U32]::IsWindowVisible($h)) { $script:found = $h; return $false }',
      '    return $true',
      '  }',
      '  [void][U32]::EnumWindows($cb2,[IntPtr]::Zero)',
      '  $dlg = $found',
      '  if ($dlg -eq [IntPtr]::Zero) { Start-Sleep -Milliseconds 400 }',
      '}',
      'if ($dlg -eq [IntPtr]::Zero) { Write-Output "NO_DIALOG"; exit 1 }',
      '[void][U32]::SetForegroundWindow($dlg)',
      'Start-Sleep -Milliseconds 500',
      'Set-Clipboard -Value $FilePath',
      '[System.Windows.Forms.SendKeys]::SendWait("^v")',
      'Start-Sleep -Milliseconds 400',
      '[System.Windows.Forms.SendKeys]::SendWait("{ENTER}")',
      'Write-Output "OK"'
    ].join('\r\n');
    try { fs.writeFileSync(ps1, '\ufeff' + script); } catch (e) { diag.layers.push('osclick write failed'); return false; }
    return await new Promise((resolve) => {
      execFile('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ps1,
        '-TitleMatch', String(opts.title || 'Google').slice(0, 30),
        '-RelX', String(opts.x), '-RelY', String(opts.y), '-InnerW', String(opts.innerW || 1280),
        '-FilePath', filePath], { timeout: 45000 }, (err, stdout) => {
        diag.layers.push('osclick: ' + (err ? 'err ' + String(((err && err.code) || '') + ' ' + ((err && err.message) || err)).slice(0, 180) : String(stdout || '').trim()));
        resolve(!err && /OK/.test(String(stdout || '')));
      });
    });
  }
  try {
    browserSession = await browser.target().createCDPSession();
    await browserSession.send('Target.setDiscoverTargets', { discover: true }).catch(() => {});
    await attachAll();

    // v0.3.29: retry the WHOLE picker round (open > hand-off > chip) up to 3
    // times. 25/26 Nov real runs: the FIRST slot uploads fine, later pickers
    // open but the handed file never starts uploading - a stall inside
    // Google's picker. Fully closing the dialog and re-opening resets it.
    async function forcePickerClosed() {
      // Inlined pickerGone: the named helper is scoped inside the retry loop
      // (caught by the stub harness - calling it here would throw on round 2+).
      const gone = async () => {
        try {
          return await page.evaluate(() => {
            for (const f of Array.from(document.querySelectorAll('iframe'))) {
              const r = f.getBoundingClientRect();
              const st = getComputedStyle(f);
              if (r.width > 250 && r.height > 250 && st.display !== 'none' && st.visibility !== 'hidden') return false;
            }
            return true;
          });
        } catch (e) { return true; }
      };
      for (let k = 0; k < 8; k++) {
        if (await gone()) return;
        const clicked = await page.evaluate(() => {
          const bs = document.querySelectorAll('button,[role=button],[aria-label]');
          for (const b of bs) {
            const t = (b.textContent || '').trim(); const al = b.getAttribute('aria-label') || '';
            if (t === '\u2715' || t === '\u00d7' || /\u0625\u063a\u0644\u0627\u0642|close/i.test(al)) { const r = b.getBoundingClientRect(); if (r.width > 5 && r.width < 90 && r.height > 5 && r.height < 90) { b.click(); return true; } }
          }
          return false;
        }).catch(() => false);
        if (!clicked) {
          for (const f of page.frames()) { if (f === page.mainFrame()) continue; try { await f.evaluate(() => { const bs = document.querySelectorAll('button,[role=button]'); for (const b of bs) { const t = (b.textContent || '').trim(); if (t === '\u2715' || t === '\u00d7') { b.click(); break; } } }); } catch (e) {} }
        }
        await sleep(800);
      }
    }
    for (let round = 0; round < 3; round++) {
    if (round > 0) {
      chooserAnswered = false;
      diag.layers.push('slot retry round ' + (round + 1));
      await forcePickerClosed();
      await sleep(3000);
    }

    // Address the upload QUESTION, never the Nth remaining button: a button
    // turns into a file chip after its upload, so indexing the remaining
    // buttons shifts whenever an earlier image is absent (25 Nov Micheal: the
    // license image landed in بطاقة وش and the backs stayed empty). The
    // container handles were snapshotted before the first upload, so they are
    // stable for the whole loop.
    const upIdx = (job && job.uploadIndex) || 0;
    let opened = false;
    if (job && job.uploadContainer) {
      try {
        const btn = await job.uploadContainer.$("xpath/.//span[contains(text(), 'إضافة ملف') or contains(text(), 'Add file')]");
        if (btn) { await clickEl(page, btn); opened = true; diag.layers.push('picker opened via container ' + upIdx); }
      } catch (e) { diag.layers.push('container click failed idx ' + upIdx + ': ' + String(e).slice(0, 60)); }
    }
    if (!opened) {
      // Fallback (no container snapshot, e.g. old test mocks): remaining-button
      // indexing - only safe when every earlier image exists.
      if (upIdx > 0) {
        await clickXNth(page, "//span[contains(text(), 'إضافة ملف') or contains(text(), 'Add file')]", upIdx, 12000);
      } else {
        await clickX(page, "//span[contains(text(), 'إضافة ملف') or contains(text(), 'Add file')]", 12000);
      }
      diag.layers.push('picker opened (remaining-index ' + upIdx + ')');
    }

    // Arm the MAIN page session too: this picker is an in-process iframe
    // (page.frames sees it), so its file chooser fires on the page target -
    // arming only OOPIF sessions is why the chooser path never answered (25 Nov).
    try { const mcs = await page.createCDPSession(); await armSession(mcs, 'page'); } catch (e) {}
    await attachAll();

    // Only a picker frame whose iframe element is CURRENTLY visible: closed
    // dialogs keep their iframe in the DOM, and handing a file to a stale
    // picker silently does nothing (25 Nov: upload #1 ok, #2 vanished).
    async function visiblePickerFrame() {
      const visSrc = await page.evaluate(() => {
        for (const f of Array.from(document.querySelectorAll('iframe'))) {
          const r = f.getBoundingClientRect();
          const st = getComputedStyle(f);
          if (r.width > 250 && r.height > 250 && st.display !== 'none' && st.visibility !== 'hidden') return f.src || '';
        }
        return '';
      }).catch(() => '');
      let best = null;
      for (const f of page.frames()) {
        let u = '';
        try { if (f === page.mainFrame()) continue; u = safeUrl(f); } catch (e) { continue; }
        if (!/picker/i.test(u)) continue;
        if (visSrc && u && visSrc.indexOf(u.slice(0, 60)) === 0) return f;
        if (!best) best = f;
      }
      return best;
    }

    // Wait for the picker dialog to actually appear (the container click is async).
    {
      const tP = Date.now();
      while (Date.now() - tP < 10000 && !(await visiblePickerFrame())) { aborted(); await sleep(400); }
    }

    // Attempt 1 (the proven mechanism): click تصفّح inside the picker and let
    // the armed chooser interception hand it the file - one deterministic
    // hand-off. The old drag-drop layer is gone for good: a drop that misses
    // the zone is what opened Micheal's images as Chrome tabs (25 Nov videos).
    for (let attempt = 0; attempt < 2 && !chooserAnswered; attempt++) {
      aborted();
      let clicked = false;
      const pf = await visiblePickerFrame();
      if (pf) {
        try {
          clicked = await pf.evaluate(() => {
            var bs = document.querySelectorAll('button,[role=button],div,span');
            for (var i = 0; i < bs.length; i++) {
              var t = (bs[i].textContent || '').trim().replace(/[\u064B-\u0652\u0640]/g, '');
              var r = bs[i].getBoundingClientRect();
              if ((t === '\u062a\u0635\u0641\u062d' || /^browse/i.test(t)) && r.width > 10 && r.width < 300 && r.height > 10 && r.height < 100) { bs[i].click(); return true; }
            }
            var inp = document.querySelector("input[type='file']");
            if (inp) { inp.click(); return true; }
            return false;
          });
        } catch (e) {}
      }
      diag.layers.push('browse click ' + (clicked ? 'ok' : 'no-picker') + ' (attempt ' + (attempt + 1) + ')');
      const t1 = Date.now();
      while (Date.now() - t1 < 8000 && !chooserAnswered) { aborted(); await sleep(250); }
    }
    if (chooserAnswered) {
      diag.layers.push('file handed via chooser');
      if (await waitChip(25000)) { diag.layers.push('chip after chooser'); await ensurePickerClosed(); return; }
      diag.layers.push('chooser answered but no chip - continuing');
    }

    // Attempt 2: set the input directly on the VISIBLE picker frame.
    if (!(await chipVisible())) {
      const pf = await visiblePickerFrame();
      if (pf) {
        try {
          const input = await pf.$("input[type='file']");
          if (input) { await input.uploadFile(filePath); diag.layers.push('file set on visible picker frame'); }
        } catch (e) {}
      }
      if (await waitChip(8000)) { diag.layers.push('chip after visible-frame set'); await ensurePickerClosed(); return; }
      diag.layers.push('visible-frame set claimed but no chip - continuing');
    }

    // Attempt 3: CDP session scan (covers a picker page.frames cannot see).
    if (!(await chipVisible())) {
      const t2 = Date.now();
      let set3 = false;
      while (Date.now() - t2 < 10000 && !set3) {
        aborted();
        await attachAll();
        set3 = await setViaSessions();
        if (!set3) await sleep(600);
      }
      if (set3 && await waitChip(8000)) { diag.layers.push('chip after session set'); await ensurePickerClosed(); return; }
      if (set3) diag.layers.push('session set claimed but no chip - continuing');
    }

    // Attempt 4 (Windows): OS-level real click + native dialog fill via PowerShell.
    if (!(await chipVisible()) && process.platform === 'win32') {
      // Disarm interception so the NATIVE dialog actually opens this time.
      for (const cs of childSessions) { if (typeof cs.send === 'function') { try { await cs.send('Page.setInterceptFileChooserDialog', { enabled: false }); } catch (e) {} } }
      try { await page.createCDPSession().then((c) => c.send('Page.setInterceptFileChooserDialog', { enabled: false })); } catch (e) {}
      const pt = await pickerButtonPoint();
      if (pt) {
        let title = ''; try { title = await page.title(); } catch (e) {}
        let innerW = 1280; try { innerW = await page.evaluate(() => window.innerWidth); } catch (e) {}
        await osClickAndFill({ title, x: pt.x, y: pt.y, innerW, filePath });
      } else {
        diag.layers.push('osclick skipped: no button point');
      }
    }

  // The chip proves the upload; the modal must ALSO be gone or it covers إرسال
  // (his 24 Nov runs: upload ok, then submit click landed on the open modal).
  async function pickerGone() {
    try {
      return await page.evaluate(() => {
        for (const f of Array.from(document.querySelectorAll('iframe'))) {
          const r = f.getBoundingClientRect();
          const st = getComputedStyle(f);
          if (r.width > 250 && r.height > 250 && st.display !== 'none' && st.visibility !== 'hidden') return false;
        }
        return true;
      });
    } catch (e) { return true; }
  }
  async function ensurePickerClosed() {
    const t0 = Date.now();
    while (Date.now() - t0 < 8000) {
      aborted();
      if (await pickerGone()) { diag.layers.push('picker closed'); return; }
      await sleep(700);
    }
    // Still open: click its ✕ (upload already attached, closing now does not
    // discard it) - then re-verify the chip survived. Frames first (in-process
    // iframes are invisible as CDP targets), sessions as fallback.
    const X_JS = "(function(){var bs=document.querySelectorAll('button,[role=button],div[aria-label]');for(var i=0;i<bs.length;i++){var t=(bs[i].textContent||'').trim();var al=(bs[i].getAttribute('aria-label')||'');if(t==='✕'||t==='×'||/إغلاق|close/i.test(al)){var r=bs[i].getBoundingClientRect();if(r.width>5&&r.width<80&&r.height>5&&r.height<80)return JSON.stringify({x:r.x+r.width/2,y:r.y+r.height/2});}}return ''})()";
    let pt = null;
    for (const f of page.frames()) {
      if (f === page.mainFrame()) continue;
      try {
        const v = await f.evaluate(X_JS);
        if (v) {
          const inner = JSON.parse(v);
          const fu = f.url();
          const off = await page.evaluate((u) => {
            const ifs = Array.from(document.querySelectorAll('iframe'));
            for (const fr of ifs) { if (u && fr.src && u.indexOf(fr.src.slice(0, 60)) === 0) { const r = fr.getBoundingClientRect(); return { x: r.x, y: r.y }; } }
            const big = ifs.map((fr) => fr.getBoundingClientRect()).filter((r2) => r2.width > 250 && r2.height > 250);
            return big.length ? { x: big[0].x, y: big[0].y } : { x: 0, y: 0 };
          }, fu).catch(() => ({ x: 0, y: 0 }));
          pt = { x: off.x + inner.x, y: off.y + inner.y };
          break;
        }
      } catch (e) {}
    }
    for (const cs of childSessions) {
      if (pt) break;
      if (typeof cs.send !== 'function') continue;
      try {
        const r = await cs.send('Runtime.evaluate', {
          expression: "(function(){var bs=document.querySelectorAll('button,[role=button],div[aria-label]');for(var i=0;i<bs.length;i++){var t=(bs[i].textContent||'').trim();var al=(bs[i].getAttribute('aria-label')||'');if(t==='✕'||t==='×'||/إغلاق|close/i.test(al)){var r=bs[i].getBoundingClientRect();if(r.width>5&&r.width<80&&r.height>5&&r.height<80)return JSON.stringify({x:r.x+r.width/2,y:r.y+r.height/2});}}return ''})()",
          returnByValue: true
        });
        const v = r && r.result && r.result.value;
        if (v) {
          const inner = JSON.parse(v);
          const href = await cs.send('Runtime.evaluate', { expression: 'location.href', returnByValue: true }).catch(() => null);
          const frameUrl = href && href.result && href.result.value ? String(href.result.value) : '';
          const off = await page.evaluate((fu) => {
            const ifs = Array.from(document.querySelectorAll('iframe'));
            for (const f of ifs) { if (fu && f.src && fu.indexOf(f.src.slice(0, 60)) === 0) { const r = f.getBoundingClientRect(); return { x: r.x, y: r.y }; } }
            const big = ifs.map((f) => f.getBoundingClientRect()).filter((r2) => r2.width > 250 && r2.height > 250);
            return big.length ? { x: big[0].x, y: big[0].y } : { x: 0, y: 0 };
          }, frameUrl).catch(() => ({ x: 0, y: 0 }));
          pt = { x: off.x + inner.x, y: off.y + inner.y };
          break;
        }
      } catch (e) {}
    }
    if (pt) {
      await page.mouse.click(pt.x, pt.y);
      diag.layers.push('picker ✕ clicked');
      const t1 = Date.now();
      while (Date.now() - t1 < 10000 && !(await pickerGone())) { aborted(); await sleep(600); }
      if (!(await chipVisible())) {
        const e = new Error('upload_not_confirmed');
        e.detail = 'chip lost after closing picker';
        e.diag = { file: fileName, layers: diag.layers, targets: diag.targets, chooserAnswered: chooserAnswered };
        throw e;
      }
      diag.layers.push('picker closed via ✕');
      return;
    }
    const e = new Error('picker_still_open');
    e.detail = 'picker modal did not close after upload and no ✕ found';
    e.diag = { file: fileName, layers: diag.layers, targets: diag.targets, chooserAnswered: chooserAnswered };
    throw e;
  }

    // Final verification: the chip (file name) must be back on the form.
    if (await waitChip(chooserAnswered ? 25000 : 15000)) {
      await ensurePickerClosed();
      return;
    }
    diag.layers.push('round ' + (round + 1) + ' ended with no chip');
    } // end retry round
    const e = new Error('upload_not_confirmed');
    e.detail = 'chip "' + fileName + '" never appeared | layers: ' + diag.layers.join(' > ').slice(0, 200) + ' | targets: ' + diag.targets.slice(0, 8).join(' ; ').slice(0, 220);
    e.diag = { file: fileName, layers: diag.layers, targets: diag.targets, chooserAnswered: chooserAnswered };
    throw e;
  } finally {
    for (const cs of childSessions) { if (typeof cs.send === 'function') { try { await cs.send('Page.setInterceptFileChooserDialog', { enabled: false }); } catch (e) {} try { await cs.detach(); } catch (e) {} } }
    try { if (browserSession) await browserSession.detach(); } catch (e) {}
  }
}

async function runFormWalk(page, job) {
  try {
    return await runFormWalkInner(page, job);
  } catch (e) {
    // False-negative guard: if the page is already on the confirmation screen,
    // the response WAS recorded no matter which step threw (24 Nov 4778672).
    const fin = await confirmState(page);
    if (fin.done) {
      return { ok: true, submitted: true, detail: 'confirmed-after-error (' + String(e && (e.detail || e.message) || '').slice(0, 150) + ')' };
    }
    throw e;
  }
}

async function runFormWalkInner(page, job) {
  const isBreak = job.action === 'break';
  const steps = [];
  let lastT = Date.now();
  const mark = (s) => {
    if (job.isAborted && job.isAborted()) { const e = new Error('aborted'); e.aborted = true; throw e; }
    const now = Date.now();
    steps.push(s + ' +' + (now - lastT) + 'ms');
    lastT = now;
  };
  const trace = () => steps.slice(-6).join(' | ');
  const fail = (err) => {
    err.detail = (err.detail ? err.detail + ' | ' : '') + 'steps: ' + trace();
    throw err;
  };

  // Wait for page 0 to actually render its controls before touching anything
  // (post-sign-in resume can land on a half-rendered page).
  {
    const t0 = Date.now();
    let ready = false;
    while (Date.now() - t0 < 15000 && !ready) {
      try {
        ready = await page.evaluate(() => !!document.querySelector("div[role='radiogroup'], div[role='checkbox'], div[role='listbox'], input[type='text']"));
      } catch (e) {}
      if (!ready) await sleep(300);
    }
    mark('page0:ready');
  }

  // Step 0: tick the Record-email consent checkbox if present and unchecked (pyw parity).
  try {
    const cb = await page.$("xpath///div[@role='checkbox']");
    if (cb) {
      const checked = await cb.evaluate((n) => n.getAttribute('aria-checked'));
      if (checked !== 'true') { await clickEl(page, cb); }
    }
    mark('page0:checkbox');
  } catch (e) { mark('page0:checkbox-skip'); }

  // Page 0: choose شيفتات الطيارين (role-scoped; section headers can't match).
  try {
    await pickOption(page, 'شيفتات الطيارين', 20000);
    mark('page0:option');
    await clickNext(page);
    mark('page0:next');
  } catch (e) { fail(e); }

  if (job.isAlex) {
    // ---- Alexandria (process_request_alex) ----
    try {
      const riderInput = (await xpAll(page, "//input[@type='text']"))[0];
      if (!riderInput) throw new Error('rider input not found');
      await typeIn(page, riderInput, job.riderId);
      mark('page1:rider');
      if (isBreak) await pickOption(page, 'البريكات', 15000);
      else await pickOption(page, 'تزويدات شيفتات الطيارين', 15000);
      mark('page1:action');
      await clickNext(page);
      mark('page1:next');
    } catch (e) { fail(e); }

    if (isBreak) {
      try { await pickOption(page, 'فك بريك', 9000); mark('page2:break-option'); } catch (e) {}
      if (job.reason) {
        // السبب: paragraph/text field on the فك بريك page; fill if present and empty.
        try {
          const ins = await xpAll(page, "//input[@type='text'] | //textarea");
          for (const i of ins) {
            const v = await i.evaluate((n) => n.value || '');
            if (!v) { await typeIn(page, i, job.reason); break; }
          }
          mark('page2:reason');
        } catch (e) {}
      }
    } else {
      // Extend: HH / MM into the time field, then AM/PM from the listbox (pyw Alex extend).
      try {
        const tins = await xpAll(page, "//input[@type='text' or @type='number']");
        if (tins.length >= 2) { await typeIn(page, tins[0], job.hh12); await typeIn(page, tins[1], job.mm); }
        mark('page2:time');
        const lb = (await xpAll(page, "//div[@role='listbox']"))[0];
        if (lb) {
          await clickEl(page, lb);
          const optX = job.isPm
            ? "//div[@role='option']//span[contains(text(), 'مساء') or contains(text(), 'PM') or contains(text(), 'م')]"
            : "//div[@role='option']//span[contains(text(), 'صباح') or contains(text(), 'AM') or contains(text(), 'ص')]";
          await clickX(page, optX, 8000);
          mark('page2:ampm');
        }
      } catch (e) {}
    }
  } else if (!job.isOpen) {
    // ---- Delta cities (process_request) ----
    try {
      await clickX(page, "//div[@role='listbox']", 15000);
      const optX = isBreak ? 'فك بريك' : 'تزويدات شيفتات الطيارين';
      await pickOption(page, optX, 15000);
      mark('page1:action');
      await clickNext(page);
      mark('page1:next');
    } catch (e) { fail(e); }

    if (!isBreak) {
      // select_time_option_smart port: pick the "إلى HH:MM ..." option from the last listbox.
      try {
        const lbs = await xpAll(page, "//div[@role='listbox']");
        if (lbs.length) {
          const wantedH = String(job.hh12).replace(/^0/, '');
          const wanted = wantedH + ':' + job.mm;
          const wantedPad = (String(job.hh12).length === 1 ? '0' + job.hh12 : job.hh12) + ':' + job.mm;
          const hh24 = job.hh24 + ':' + job.mm;
          const pmK = ['مساء', 'بليل', 'الظهر', 'العصر', 'pm', 'م'];
          const amK = ['صباح', 'الصبح', 'الفجر', 'am', 'ص'];
          let picked = false;
          // Up to 3 full attempts (24 Nov الغردقة: an option got clicked but the
          // field never committed - verify the listbox text actually changed).
          for (let attempt = 0; attempt < 3 && !picked; attempt++) {
            await clickEl(page, lbs[lbs.length - 1]);
            let clicked = false;
            for (let pass = 0; pass < 20 && !clicked; pass++) {
              const opts = await xpAll(page, "//div[@role='option']");
              for (const o of opts) {
                // Only options actually on screen: a stale/hidden popup can
                // match the text first and eat the click (24 Nov).
                const vis = await o.evaluate((n) => { const r = n.getBoundingClientRect(); return r.width > 4 && r.height > 4; }).catch(() => false);
                if (!vis) continue;
                const val = String(await o.evaluate((n) => n.getAttribute('data-value') || n.innerText || '')).replace(/ /g, ' ').trim().toLowerCase();
                if (!val) continue;
                if (val.indexOf(wanted) < 0 && val.indexOf(wantedPad) < 0 && val.indexOf(hh24) < 0) continue;
                const hasPm = pmK.some((k) => val.indexOf(k) >= 0);
                const hasAm = amK.some((k) => val.indexOf(k) >= 0);
                if ((job.isPm && (hasPm || !hasAm)) || (!job.isPm && (hasAm || !hasPm))) {
                  await clickEl(page, o); clicked = true; break;
                }
              }
              if (!clicked) await sleep(200);
            }
            if (clicked) {
              await sleep(500);
              const shown = await page.evaluate(() => { const ls = document.querySelectorAll("div[role='listbox']"); const lb = ls[ls.length - 1]; return lb ? String(lb.textContent || '') : ''; }).catch(() => '');
              // Positive match only: the placeholder "اختيار" can linger inside
              // the control even after a real selection (24 Nov false negative).
              if (shown.indexOf(wanted) >= 0 || shown.indexOf(wantedPad) >= 0 || shown.indexOf(hh24) >= 0) picked = true;
              // else the click did not commit: loop re-opens the dropdown.
            }
          }
          mark(picked ? 'page2:time-pick' : 'page2:time-pick-unverified');
        }
      } catch (e) {}
    }

    // Rider + city text inputs (pyw: last two inputs, or the single one).
    try {
      const tins = await xpAll(page, "//input[@type='text']");
      if (tins.length === 1) { await typeIn(page, tins[0], job.riderId); }
      else if (tins.length >= 2) {
        await typeIn(page, tins[tins.length - 2], job.riderId);
        await typeIn(page, tins[tins.length - 1], job.cityVal);
      }
      mark('page2:rider-city');
    } catch (e) {}
  }

  if (job.isOpen) {
    // ---- فتح شيفت (Delta form, 24 Nov): page 1 listbox -> 'قفل او رفع او فتح شيفت',
    // page 2: kind listbox (فتح شيفت), السبب / رقم المركبة / Rider ID / المدينة texts,
    // الإثبات file upload (app-generated black proof image).
    try {
      await clickX(page, "//div[@role='listbox']", 15000);
      await pickOption(page, 'قفل او رفع او فتح شيفت', 15000);
      await sleep(500);
      // Verify the dropdown committed; re-select once if it didn't stick.
      try {
        const shown = await page.evaluate(() => { const lb = document.querySelector("div[role='listbox']"); return lb ? lb.textContent || '' : ''; });
        if (shown.indexOf('قفل') < 0) {
          await clickX(page, "//div[@role='listbox']", 8000);
          await pickOption(page, 'قفل او رفع او فتح شيفت', 8000);
          await sleep(500);
        }
      } catch (e) {}
      mark('page1:action');
      await clickNext(page);
      mark('page1:next');
      await clickX(page, "//div[@role='listbox']", 12000);
      await pickOption(page, 'فتح شيفت', 9000);
      await sleep(500);
      try {
        const shown = await page.evaluate(() => { const lb = document.querySelector("div[role='listbox']"); return lb ? lb.textContent || '' : ''; });
        if (shown.indexOf('فتح') < 0) {
          await clickX(page, "//div[@role='listbox']", 8000);
          await pickOption(page, 'فتح شيفت', 8000);
          await sleep(500);
        }
      } catch (e) {}
      mark('page2:kind');
      const tins = await xpAll(page, "//input[@type='text']");
      // Field order on the live page: السبب, رقم المركبة, Rider ID, المدينة.
      const vals = [job.reason, job.vehicle, job.riderId, job.cityVal];
      for (let i = 0; i < tins.length && i < vals.length; i++) {
        if (vals[i]) await typeIn(page, tins[i], vals[i]);
      }
      mark('page2:fields');
      if (job.manualProof) { mark('page2:upload-manual'); } else { await uploadProof(page, job.proofPath, job); mark('page2:upload'); }
    } catch (e) { fail(e); }
  }

  // Manual proof mode (Micheal 24 Nov): the app filled everything; HE attaches
  // the image and presses إرسال himself. The app only watches for the
  // confirmation and records the result.
  if (job.manualProof) {
    mark('manual-proof-wait');
    if (job.onManualWait) { try { job.onManualWait(); } catch (e) {} }
    const tM = Date.now();
    while (Date.now() - tM < 360000) {
      if (job.isAborted && job.isAborted()) { const ab = new Error('aborted'); ab.aborted = true; throw ab; }
      try {
        const fin = await confirmState(page);
        if (fin.done) { mark('manual:confirmed'); return { ok: true, submitted: true, detail: 'steps: ' + steps.join(' | ') }; }
      } catch (e) {}
      await sleep(2000);
    }
    return { ok: false, error: 'manual_timeout', uncertain: true, submitted: false, detail: 'steps: ' + steps.join(' | ') };
  }

  // Submit (never in test/dry mode - real submissions only on Micheal's explicit taps).
  if (job.dryRun) return { ok: true, dryRun: true, submitted: false, detail: 'steps: ' + steps.join(' | ') };
  try {
    // Never submit after an abort - the Stop button must be final (24 Nov).
    if (job.isAborted && job.isAborted()) { const ab = new Error('aborted'); ab.aborted = true; throw ab; }
    // Wait until no overlay (picker modal) covers إرسال: his 24 Nov runs had the
    // upload done but the submit click swallowed by the still-open modal.
    {
      const tS = Date.now();
      let clear = false;
      while (Date.now() - tS < 15000 && !clear) {
        try {
          clear = await page.evaluate(() => {
            const spans = Array.from(document.querySelectorAll('span')).filter((s) => /إرسال|Submit/.test(s.textContent || ''));
            for (const s of spans) {
              const r = s.getBoundingClientRect();
              if (r.width < 2 || r.height < 2) continue;
              const el = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2);
              if (el && (el === s || s.contains(el) || el.contains(s))) return true;
            }
            return false;
          });
        } catch (e) {}
        if (!clear) await sleep(500);
      }
      if (!clear) { const e = new Error('submit_covered'); e.detail = 'an overlay still covers إرسال after 15s'; throw e; }
      mark('submit:uncovered');
      // One deliberate beat with the filled form on screen before إرسال (24 Nov).
      await sleep(1200);
    }
    if (job.onSubmitting) job.onSubmitting();
    await clickX(page, SUBMIT_X, 15000);
    mark('submit:clicked');
  } catch (e) { fail(e); }
  const res = await waitConfirmation(page, job.isOpen ? 25000 : 10000);
  mark('submit:confirmed');
  res.detail = (res.detail ? res.detail + ' | ' : '') + 'steps: ' + steps.join(' | ');
  return res;
}

// ---- رفع الاستعلام: فورم تعيينات الطيارين walk (24 Nov, Micheal 12527112) ----
// Single-page form: 4 dropdowns (office, hire_type, lecture_office, vehicle),
// 6 text fields in order, 5 file-upload questions. Dry mode fills everything and
// stops before إرسال; real runs are only ever for requests Micheal approved on
// the site.

// Open the dropdown at page-order INDEX and pick the option by its text. The
// commit check is a POSITIVE match on that same listbox: the placeholder
// 'اختيار' can stay in textContent after a real selection (24 Nov), so only the
// chosen value proves the commit. One retry on a missed commit.
async function pickFromListbox(page, index, text, timeoutMs) {
  const open = async () => {
    const t0 = Date.now();
    while (Date.now() - t0 < (timeoutMs || 12000)) {
      const lbs = await xpAll(page, "//div[@role='listbox']");
      if (lbs[index]) {
        try { await clickEl(page, lbs[index]); return; } catch (e) {}
      }
      await sleep(200);
    }
    throw new Error('listbox ' + index + ' not found');
  };
  const shown = async () => {
    try {
      return await page.evaluate((i) => {
        const ls = document.querySelectorAll("div[role='listbox']");
        const lb = ls[i];
        return lb ? String(lb.textContent || '') : '';
      }, index);
    } catch (e) { return ''; }
  };
  await open();
  await sleep(400); // let the option overlay render
  await pickOption(page, text, timeoutMs || 12000);
  if ((await shown()).indexOf(text) >= 0) return;
  await open();
  await sleep(400);
  await pickOption(page, text, 8000);
  if ((await shown()).indexOf(text) < 0) {
    const e = new Error('dropdown_commit_failed: ' + text);
    e.detail = 'listbox ' + index + ' never showed "' + text + '"';
    throw e;
  }
}

async function runHiringWalk(page, job) {
  // job: { dry, payload:{office,hire_type,sup_name,lecture_office,rider_name,
  //   rider_phone,rider_nid,license_no,rider_addr,vehicle}, files:{img_*: path},
  //   isAborted, onSubmitting, uploadImpl (test hook only) }
  const steps = [];
  // Stray-tab guard (25 Nov): misfired clicks used to open the uploaded images
  // as extra Chrome tabs. Remember which tabs existed before the walk and close
  // any NEW tab when the walk ends, success or failure.
  let tabsBefore = null;
  try { tabsBefore = new Set(await page.browser().pages()); } catch (e) {}
  // NEVER let a local file open as a tab: a missed drop/click during uploads
  // used to navigate Chrome to file://... (25 Nov Micheal videos). Close any
  // file:// target the moment it appears, for the whole walk.
  const killFileTab = async (t) => {
    try {
      const u = (t && t.url && t.url()) || '';
      if (!u.startsWith('file://')) return;
      const p = await t.page().catch(() => null);
      if (p && p !== page) await p.close().catch(() => {});
    } catch (e) {}
  };
  try { page.browser().on('targetcreated', killFileTab); page.browser().on('targetchanged', killFileTab); } catch (e) {}
  const closeNewTabs = async () => {
    try { page.browser().off('targetcreated', killFileTab); page.browser().off('targetchanged', killFileTab); } catch (e) {}
    if (!tabsBefore) return 0;
    let closed = 0;
    let pages = [];
    try { pages = await page.browser().pages(); } catch (e) {}
    for (const p of pages) {
      if (p === page || tabsBefore.has(p)) continue;
      try { await p.close(); closed++; } catch (e) {}
    }
    return closed;
  };
  let lastT = Date.now();
  const mark = (s) => {
    if (job.isAborted && job.isAborted()) { const e = new Error('aborted'); e.aborted = true; throw e; }
    const now = Date.now();
    steps.push(s + ' +' + (now - lastT) + 'ms');
    lastT = now;
  };
  const fail = (err) => {
    err.detail = (err.detail ? err.detail + ' | ' : '') + 'steps: ' + steps.slice(-6).join(' | ');
    throw err;
  };
  const uploader = job.uploadImpl || uploadProof;
  try {
    {
      const t0 = Date.now();
      let ready = false;
      while (Date.now() - t0 < 15000 && !ready) {
        try { ready = await page.evaluate(() => !!document.querySelector("div[role='listbox'], input[type='text']")); } catch (e) {}
        if (!ready) await sleep(300);
      }
      if (!ready) throw new Error('form_not_ready');
    }
    mark('page:ready');
    // Tick the record-email consent checkbox if present and unchecked.
    try {
      const cb = await page.$("xpath///div[@role='checkbox']");
      if (cb) {
        const checked = await cb.evaluate((n) => n.getAttribute('aria-checked'));
        if (checked !== 'true') await clickEl(page, cb);
      }
    } catch (e) {}
    mark('checkbox');

    // Dropdowns in page order: office=0, hire_type=1, lecture_office=2, vehicle=3.
    await pickFromListbox(page, 0, job.payload.office, 15000); mark('dd:office');
    await pickFromListbox(page, 1, job.payload.hire_type, 15000); mark('dd:hire_type');
    await pickFromListbox(page, 2, job.payload.lecture_office, 15000); mark('dd:lecture_office');

    // Text fields in page order: sup_name, rider_name, phone, nid, license, address.
    const texts = [job.payload.sup_name, job.payload.rider_name, job.payload.rider_phone,
      job.payload.rider_nid, job.payload.license_no || '', job.payload.rider_addr];
    const tins = await xpAll(page, "//input[@type='text']");
    if (tins.length < 6) throw new Error('expected 6 text inputs, found ' + tins.length);
    for (let i = 0; i < texts.length; i++) { if (texts[i]) await typeIn(page, tins[i], texts[i]); }
    mark('texts:6');

    await pickFromListbox(page, 3, job.payload.vehicle, 15000); mark('dd:vehicle');

    // Upload questions are addressed by their TITLE WORDS, never by button
    // index (25 Nov Micheal: an uploaded question's إضافة ملف button becomes a
    // chip, so counting remaining buttons shifts and images land in the wrong
    // questions). Titles from the live form + docs/hiring-form-fields.json:
    //   صوره الرخصه "الوش" / "الضهر" (optional),
    //   صوره بطاقة الطيار - الوش / الضهر (required), الصوره الشخصيه (required).
    const UPLOAD_SLOTS = [
      { key: 'img_license_front', words: ['الرخص', 'الوش'], required: false },
      { key: 'img_license_back', words: ['الرخص', 'الضهر'], required: false },
      { key: 'img_nid_front', words: ['بطاق', 'الطيار', 'الوش'], required: true },
      { key: 'img_nid_back', words: ['بطاق', 'الطيار', 'الضهر'], required: true },
      { key: 'img_personal', words: ['شخصي'], required: true }
    ];
    // Google renders lower questions lazily: walk the page once so all five
    // upload questions exist in the DOM before locating them.
    try {
      await page.evaluate(async () => {
        const h = (document.scrollingElement || document.body).scrollHeight;
        for (let y = 0; y <= h; y += 600) { window.scrollTo(0, y); await new Promise((r) => setTimeout(r, 120)); }
        window.scrollTo(0, 0);
      });
    } catch (e) {}
    const findSlot = async (slot) => {
      const items = await xpAll(page, "//div[@role='listitem']");
      for (const it of items) {
        let t = '';
        try {
          t = await it.evaluate((n) => {
            const h = n.querySelector('[role="heading"]');
            return (((h && h.textContent) || n.textContent || '')).replace(/\s+/g, '');
          });
        } catch (e) { continue; }
        if (slot.words.every((w) => t.includes(w))) return it;
      }
      return null;
    };
    const chipState = (li) => li.evaluate((n) => {
      const btn = n.ownerDocument.evaluate(".//span[contains(text(), 'إضافة ملف') or contains(text(), 'Add file')]", n, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
      return { hasBtn: !!btn, text: (n.textContent || '').replace(/\s+/g, '') };
    });
    for (let i = 0; i < UPLOAD_SLOTS.length; i++) {
      const slot = UPLOAD_SLOTS[i];
      const fp = job.files && job.files[slot.key];
      if (!fp) {
        // Never submit with a required slot empty: fail loudly instead
        // (Google would reject the submit anyway, looking like a walker bug).
        if (slot.required && !job.dry) { const e = new Error('صورة مطلوبة ناقصة من الطلب: ' + slot.key); e.detail = 'missing required image ' + slot.key; throw e; }
        continue;
      }
      const container = await findSlot(slot);
      if (!container) { const e = new Error('سؤال الرفع غير موجود في الفورم: ' + slot.key); e.detail = 'question not found ' + slot.key; throw e; }
      try { await container.evaluate((n) => { try { n.scrollIntoView({ block: 'center' }); } catch (e) {} }); } catch (e) {}
      await uploader(page, fp, Object.assign({}, job, { uploadIndex: i, uploadContainer: container }));
      // Verify THIS question took the file: its chip carries the file name or
      // its إضافة ملف button is gone. A page-wide chip proves nothing - the
      // same file in two questions is exactly the bug being fixed.
      const fname = path.basename(fp).replace(/\s+/g, '');
      let vs = { hasBtn: true, text: '' };
      try { vs = await chipState(container); } catch (e) {}
      if (vs.hasBtn && !vs.text.includes(fname)) {
        const e = new Error('الصورة لم تدخل سؤالها الصحيح: ' + slot.key);
        e.detail = 'verify failed ' + slot.key + ' file ' + fname;
        throw e;
      }
      mark('upload:' + slot.key);
      // Let Google finish registering this upload before opening the next
      // picker - back-to-back uploads race and the later chip never lands.
      await sleep(2500);
    }
    // Pre-submit guard: every REQUIRED upload question must hold a chip.
    if (!job.dry) {
      for (const slot of UPLOAD_SLOTS) {
        if (!slot.required) continue;
        const c2 = await findSlot(slot);
        let okc = false;
        if (c2) { try { const s2 = await chipState(c2); okc = !s2.hasBtn; } catch (e) {} }
        if (!okc) { const e = new Error('خانة مطلوبة فاضية قبل الإرسال: ' + slot.key); e.detail = 'required slot empty before submit ' + slot.key; throw e; }
      }
      mark('verify:required-uploads');
    }

    if (job.dry) {
      mark('dry:stop-before-submit');
      const closedDry = await closeNewTabs();
      return { ok: true, submitted: false, dry: true, detail: 'dry run - filled, stopped before إرسال | steps: ' + steps.join(' | ') + (closedDry ? ' | closed ' + closedDry + ' stray tabs' : '') };
    }
    if (job.onSubmitting) job.onSubmitting();
    await clickX(page, SUBMIT_X, 15000);
    mark('submit:clicked');
  } catch (e) { try { await closeNewTabs(); } catch (e2) {} fail(e); }
  const res = await waitConfirmation(page, 25000);
  mark('submit:confirmed');
  const closedTabs = await closeNewTabs();
  res.detail = (res.detail ? res.detail + ' | ' : '') + 'steps: ' + steps.join(' | ') + (closedTabs ? ' | closed ' + closedTabs + ' stray tabs' : '');
  return res;
}

module.exports = { runFormWalk, runHiringWalk, clickX, clickXNth, pageMarker, confirmState, ANOTHER_X, uploadProof };
