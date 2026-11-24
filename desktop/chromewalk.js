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
        return;
      } catch (e) { lastErr = e; }
    }
    await sleep(150);
  }
  const e = lastErr || new Error('timeout clicking ' + x.slice(0, 70));
  e.detail = 'click target: ' + x.slice(0, 90);
  throw e;
}

// Trusted click on a specific element handle: real mouse event at its center.
async function clickEl(page, el) {
  await el.evaluate((n) => { try { n.scrollIntoView({ block: 'center' }); } catch (e) {} });
  await sleep(80);
  const box = await el.boundingBox();
  if (!box) throw new Error('element not visible');
  await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
}
// Trusted typing into a specific handle: mouse-click it, then real keys.
async function typeIn(page, el, text) {
  await clickEl(page, el);
  await page.keyboard.type(String(text), { delay: 15 });
  await sleep(60);
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

// Google Forms file upload (v0.3.12). The Docs picker is a cross-origin OOPIF,
// so a plain page.frames() scan can miss its <input type=file>. Three layers:
//  1) puppeteer frame scan (fast path when the OOPIF is exposed);
//  2) raw-CDP scan of EVERY attached target session: DOM.querySelector the
//     file input and DOM.setFileInputFiles on that session directly;
//  3) trusted click on the picker's تصفّح button (viewport coords computed
//     from the iframe rect + button rect) while every target session intercepts
//     the file chooser, answering it with the proof PNG.
// The step passes only when the file's chip (its name) is visible back on the
// form; otherwise it throws and the walk never reaches إرسال.
async function uploadProof(page, filePath, job) {
  const fileName = path.basename(filePath || '') || 'proof.png';
  const browser = page.browser();
  const armed = [];
  let chooserAnswered = false;
  const armSession = async (s) => {
    try {
      await s.send('Page.enable').catch(() => {});
      await s.send('Page.setInterceptFileChooserDialog', { enabled: true }).catch(() => {});
      s.on('Page.fileChooserOpened', async (ev) => {
        try {
          await s.send('DOM.setFileInputFiles', { files: [filePath], backendNodeId: ev.backendNodeId });
          chooserAnswered = true;
        } catch (e) {}
      });
      armed.push(s);
    } catch (e) {}
  };
  const armTarget = async (t) => {
    try {
      if (!t) return;
      const ty = t.type();
      if (ty === 'browser' || ty === 'service_worker' || ty === 'background_page' || ty === 'shared_worker') return;
      await armSession(await t.createCDPSession());
    } catch (e) {}
  };
  for (const t of browser.targets()) await armTarget(t);
  const onNewTarget = (t) => { armTarget(t); };
  browser.on('targetcreated', onNewTarget);
  const disarm = async () => {
    try { browser.off('targetcreated', onNewTarget); } catch (e) {}
    for (const s of armed) { try { await s.send('Page.setInterceptFileChooserDialog', { enabled: false }); } catch (e) {} }
  };
  // Set files on the first session (frame) that exposes an <input type=file>.
  const setViaCdp = async () => {
    for (const s of armed) {
      try {
        await s.send('DOM.enable').catch(() => {});
        const doc = await s.send('DOM.getDocument', { depth: 1 });
        const q = await s.send('DOM.querySelector', { nodeId: doc.root.nodeId, selector: "input[type='file']" });
        if (q && q.nodeId) {
          await s.send('DOM.setFileInputFiles', { files: [filePath], nodeId: q.nodeId });
          return true;
        }
      } catch (e) {}
    }
    return false;
  };
  try {
    await clickX(page, "//span[contains(text(), 'إضافة ملف') or contains(text(), 'Add file')]", 12000);
    let set = false;
    const t0 = Date.now();
    while (Date.now() - t0 < 10000 && !set) {
      // Layer 1: puppeteer frames.
      for (const f of page.frames()) {
        let input = null;
        try { input = await f.$("input[type='file']"); } catch (e) {}
        if (input) { try { await input.uploadFile(filePath); set = true; } catch (e) {} }
        if (set) break;
      }
      // Layer 2: raw-CDP per-session scan (catches OOPIFs puppeteer misses).
      if (!set) { try { set = await setViaCdp(); } catch (e) {} }
      if (!set) await sleep(500);
    }
    if (!set && !chooserAnswered) {
      // Layer 3: trusted-click تصفّح; the intercepted chooser receives the file.
      let pt = null;
      for (const s of armed) {
        try {
          const r = await s.send('Runtime.evaluate', {
            expression: "(function(){var bs=document.querySelectorAll('button,[role=button]');for(var i=0;i<bs.length;i++){var t=(bs[i].textContent||'').trim();if(t==='تصفّح'||t==='تصفح'||t==='Browse'){var r=bs[i].getBoundingClientRect();if(r.width>2)return JSON.stringify({x:r.x+r.width/2,y:r.y+r.height/2});}}return ''})()",
            returnByValue: true
          });
          const v = r && r.result && r.result.value;
          if (v) {
            const inner = JSON.parse(v);
            // Translate frame-local coords to viewport coords via the picker iframe rect.
            const fr = await s.send('Runtime.evaluate', { expression: 'location.href', returnByValue: true }).catch(() => null);
            const frameUrl = fr && fr.result && fr.result.value ? String(fr.result.value) : '';
            const off = await page.evaluate((fu) => {
              const ifs = Array.from(document.querySelectorAll('iframe'));
              for (const f of ifs) {
                if (fu && f.src && fu.indexOf(f.src.slice(0, 60)) === 0) {
                  const r = f.getBoundingClientRect();
                  return { x: r.x, y: r.y };
                }
              }
              const big = ifs.map((f) => f.getBoundingClientRect()).filter((r) => r.width > 200 && r.height > 200);
              return big.length ? { x: big[0].x, y: big[0].y } : { x: 0, y: 0 };
            }, frameUrl).catch(() => ({ x: 0, y: 0 }));
            pt = { x: off.x + inner.x, y: off.y + inner.y };
            break;
          }
        } catch (e) {}
      }
      if (pt) {
        await page.mouse.click(pt.x, pt.y);
        const t1 = Date.now();
        while (Date.now() - t1 < 12000 && !chooserAnswered) await sleep(300);
      }
      if (!chooserAnswered) {
        const e = new Error('upload_input_not_found');
        e.detail = pt ? 'chooser not intercepted after تصفّح click' : 'no file input in any frame/session and no تصفّح button';
        throw e;
      }
    }
    // Verify: the file chip (its name) must appear back on the form page.
    const t2 = Date.now();
    let chip = false;
    while (Date.now() - t2 < 60000 && !chip) {
      if (job && job.isAborted && job.isAborted()) { const ab = new Error('aborted'); ab.aborted = true; throw ab; }
      try {
        chip = await page.evaluate((fn) => ((document.body && document.body.innerText) || '').indexOf(fn) >= 0, fileName);
      } catch (e) {}
      if (!chip) await sleep(800);
    }
    if (!chip) {
      const e = new Error('upload_not_confirmed');
      e.detail = 'file chip "' + fileName + '" not visible on the form after 60s';
      throw e;
    }
  } finally {
    await disarm();
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
          await clickEl(page, lbs[lbs.length - 1]);
          const wantedH = String(job.hh12).replace(/^0/, '');
          const wanted = wantedH + ':' + job.mm;
          const wantedPad = (job.hh12.length === 1 ? '0' + job.hh12 : job.hh12) + ':' + job.mm;
          const hh24 = job.hh24 + ':' + job.mm;
          const pmK = ['مساء', 'بليل', 'الظهر', 'العصر', 'pm', 'م'];
          const amK = ['صباح', 'الصبح', 'الفجر', 'am', 'ص'];
          let picked = false;
          for (let pass = 0; pass < 20 && !picked; pass++) {
            const opts = await xpAll(page, "//div[@role='option']");
            for (const o of opts) {
              const val = String(await o.evaluate((n) => n.getAttribute('data-value') || n.innerText || '')).replace(/ /g, ' ').trim().toLowerCase();
              if (!val) continue;
              if (val.indexOf(wanted) < 0 && val.indexOf(wantedPad) < 0 && val.indexOf(hh24) < 0) continue;
              const hasPm = pmK.some((k) => val.indexOf(k) >= 0);
              const hasAm = amK.some((k) => val.indexOf(k) >= 0);
              if ((job.isPm && (hasPm || !hasAm)) || (!job.isPm && (hasAm || !hasPm))) {
                await clickEl(page, o); picked = true; break;
              }
            }
            if (!picked) await sleep(200);
          }
          mark('page2:time-pick');
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
      await uploadProof(page, job.proofPath, job);
      mark('page2:upload');
    } catch (e) { fail(e); }
  }

  // Submit (never in test/dry mode - real submissions only on Micheal's explicit taps).
  if (job.dryRun) return { ok: true, dryRun: true, submitted: false, detail: 'steps: ' + steps.join(' | ') };
  try {
    // Never submit after an abort - the Stop button must be final (24 Nov).
    if (job.isAborted && job.isAborted()) { const ab = new Error('aborted'); ab.aborted = true; throw ab; }
    if (job.onSubmitting) job.onSubmitting();
    await clickX(page, SUBMIT_X, 15000);
    mark('submit:clicked');
  } catch (e) { fail(e); }
  const res = await waitConfirmation(page, 10000);
  mark('submit:confirmed');
  res.detail = (res.detail ? res.detail + ' | ' : '') + 'steps: ' + steps.join(' | ');
  return res;
}

module.exports = { runFormWalk, clickX, pageMarker, confirmState, ANOTHER_X };
