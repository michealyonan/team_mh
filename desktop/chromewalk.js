// team_mh desktop v0.3.5 - Google Forms walk inside REAL Chrome (puppeteer-core).
// Node-side driver using TRUSTED input events (real mouse clicks / keyboard.type),
// the exact equivalent of Selenium's click()/send_keys() in Micheal's Python tool.
// v0.3.5: speed pass - event-based waits instead of fixed sleeps (page-advance is
// detected via the hidden pageHistory marker, options are awaited not slept on),
// and per-step timings in every result so we can see where the time goes.
//
// Step order mirrors process_request / process_request_alex / select_time_option_smart.

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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
  await clickX(page, "//span[contains(text(), '" + text + "')]", 8000);
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
  await clickX(page, NEXT_X, timeoutMs || 15000);
  const t0 = Date.now();
  while (Date.now() - t0 < 8000) {
    await sleep(120);
    const after = await pageMarker(page);
    if (after && after !== before) return;
  }
  const err = await page.evaluate(() => {
    const m = document.body ? document.body.innerText.match(/[^\n]*(?:مطلوب|required question)[^\n]*/i) : null;
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
        required: /مطلوب|required question/i.test(t),
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
    const now = Date.now();
    steps.push(s + ' +' + (now - lastT) + 'ms');
    lastT = now;
  };
  const trace = () => steps.slice(-6).join(' | ');
  const fail = (err) => {
    err.detail = (err.detail ? err.detail + ' | ' : '') + 'steps: ' + trace();
    throw err;
  };

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
  } else {
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

  // Submit (never in test/dry mode - real submissions only on Micheal's explicit taps).
  if (job.dryRun) return { ok: true, dryRun: true, submitted: false, detail: 'steps: ' + steps.join(' | ') };
  try {
    await clickX(page, SUBMIT_X, 15000);
    mark('submit:clicked');
  } catch (e) { fail(e); }
  const res = await waitConfirmation(page, 10000);
  mark('submit:confirmed');
  res.detail = (res.detail ? res.detail + ' | ' : '') + 'steps: ' + steps.join(' | ');
  return res;
}

module.exports = { runFormWalk, clickX, pageMarker, confirmState, ANOTHER_X };
