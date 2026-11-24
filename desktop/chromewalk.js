// team_mh desktop v0.3.3 - Google Forms walk inside REAL Chrome (puppeteer-core).
// Node-side driver using TRUSTED input events (ElementHandle.click / keyboard.type),
// the exact equivalent of Selenium's click()/send_keys() in Micheal's Python tool.
// v0.3.1's in-page evaluate used untrusted el.click()/execCommand: radio clicks
// registered, but Google Forms' text fields IGNORE untrusted typing, so Rider ID
// stayed empty, Next bounced on validation, and the walk died (walk_exception).
//
// Step order/waits mirror process_request / process_request_alex / select_time_option_smart.

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const NEXT_X = "//span[contains(text(), 'التالي') or contains(text(), 'Next')]";
const SUBMIT_X = "//span[contains(text(), 'إرسال') or contains(text(), 'Submit')]";

async function xpFirst(page, x, timeoutMs) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    const el = await page.$('xpath/' + x);
    if (el) return el;
    await sleep(300);
  }
  throw new Error('timeout waiting ' + x.slice(0, 70));
}
async function xpAll(page, x) {
  try { return await page.$$('xpath/' + x); } catch (e) { return []; }
}
// Pick a form OPTION by text: strictly prefer role-scoped matches (radio/option)
// so a section header carrying the same words can never swallow the click.
async function pickOption(page, text, timeoutMs) {
  const t0 = Date.now();
  const scoped = "//div[@role='radio']//span[contains(text(), '" + text + "')] | //div[@role='option']//span[contains(text(), '" + text + "')] | //div[@role='checkbox']//span[contains(text(), '" + text + "')]";
  while (Date.now() - t0 < (timeoutMs || 12000)) {
    let el = await page.$('xpath/' + scoped);
    if (el) { await clickEl(el); return; }
    await sleep(300);
  }
  clickEl(await xpFirst(page, "//span[contains(text(), '" + text + "')]", 6000));
}
async function clickEl(el) {
  await el.evaluate((n) => { try { n.scrollIntoView({ block: 'center' }); } catch (e) {} });
  await sleep(150);
  await el.click(); // trusted mouse click (Selenium parity)
}
async function typeIn(page, el, text) {
  await el.evaluate((n) => { try { n.scrollIntoView({ block: 'center' }); } catch (e) {} });
  await el.click();
  await sleep(120);
  await page.keyboard.type(String(text), { delay: 40 }); // trusted keys (send_keys parity)
  await sleep(150);
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

// Click Next and confirm the page actually advanced; if Google bounced us back with
// a validation error, report which required answer it complained about.
async function clickNext(page, timeoutMs) {
  const before = await pageMarker(page);
  clickEl(await xpFirst(page, NEXT_X, timeoutMs || 12000));
  await sleep(1800);
  const after = await pageMarker(page);
  if (after && before && after === before) {
    const err = await page.evaluate(() => {
      const m = document.body ? document.body.innerText.match(/[^\n]*(?:مطلوب|required)[^\n]*/i) : null;
      return m ? m[0].slice(0, 120) : '';
    });
    const e = new Error('validation_blocked' + (err ? ': ' + err : ''));
    e.code = 'validation_blocked';
    throw e;
  }
}

async function runFormWalk(page, job) {
  const isBreak = job.action === 'break';

  // Step 0: tick the Record-email consent checkbox if present and unchecked (pyw parity).
  try {
    const cb = await page.$("xpath///div[@role='checkbox']");
    if (cb) {
      const checked = await cb.evaluate((n) => n.getAttribute('aria-checked'));
      if (checked !== 'true') { await clickEl(cb); await sleep(500); }
    }
  } catch (e) {}

  // Page 0: choose شيفتات الطيارين (role-scoped; section headers can't match).
  await pickOption(page, 'شيفتات الطيارين', 25000);
  await sleep(500);
  await clickNext(page);

  if (job.isAlex) {
    // ---- Alexandria (process_request_alex) ----
    // Page 1: Rider ID text input (first text input on the page), then the action.
    const riderInput = await xpFirst(page, "//input[@type='text']", 15000);
    await typeIn(page, riderInput, job.riderId);
    await sleep(300);
    if (isBreak) await pickOption(page, 'البريكات', 15000);
    else await pickOption(page, 'تزويدات شيفتات الطيارين', 15000);
    await sleep(500);
    await clickNext(page);

    if (isBreak) {
      try { await pickOption(page, 'فك بريك', 9000); await sleep(300); } catch (e) {}
      if (job.reason) {
        // السبب is a paragraph/text field on the فك بريك page; fill if present.
        try {
          const ins = await xpAll(page, "//input[@type='text'] | //textarea");
          for (const i of ins) {
            const v = await i.evaluate((n) => n.value || '');
            if (!v) { await typeIn(page, i, job.reason); break; }
          }
        } catch (e) {}
      }
    } else {
      // Extend: HH / MM into the time field, then AM/PM from the listbox (pyw Alex extend).
      try {
        const tins = await xpAll(page, "//input[@type='text' or @type='number']");
        if (tins.length >= 2) { await typeIn(page, tins[0], job.hh12); await typeIn(page, tins[1], job.mm); await sleep(300); }
        const lb = await page.$("xpath///div[@role='listbox']");
        if (lb) {
          await clickEl(lb);
          const optX = job.isPm
            ? "//div[@role='option']//span[contains(text(), 'مساء') or contains(text(), 'PM') or contains(text(), 'م')]"
            : "//div[@role='option']//span[contains(text(), 'صباح') or contains(text(), 'AM') or contains(text(), 'ص')]";
          clickEl(await xpFirst(page, optX, 12000));
          await sleep(300);
        }
      } catch (e) {}
    }
  } else {
    // ---- Delta cities (process_request) ----
    clickEl(await xpFirst(page, "//div[@role='listbox']", 15000));
    await sleep(1200);
    const optX = isBreak ? 'فك بريك' : 'تزويدات شيفتات الطيارين';
    await pickOption(page, optX, 15000);
    await sleep(500);
    await clickNext(page);

    if (!isBreak) {
      // select_time_option_smart port: pick the "إلى HH:MM ..." option from the last listbox.
      try {
        const lbs = await xpAll(page, "//div[@role='listbox']");
        if (lbs.length) {
          const lb = lbs[lbs.length - 1];
          await clickEl(lb);
          await sleep(1500);
          const wantedH = String(job.hh12).replace(/^0/, '');
          const wanted = wantedH + ':' + job.mm;
          const wantedPad = (job.hh12.length === 1 ? '0' + job.hh12 : job.hh12) + ':' + job.mm;
          const hh24 = job.hh24 + ':' + job.mm;
          const pmK = ['مساء', 'بليل', 'الظهر', 'العصر', 'pm', 'م'];
          const amK = ['صباح', 'الصبح', 'الفجر', 'am', 'ص'];
          let picked = false;
          for (let pass = 0; pass < 30 && !picked; pass++) {
            const opts = await xpAll(page, "//div[@role='option']");
            for (const o of opts) {
              const val = String(await o.evaluate((n) => n.getAttribute('data-value') || n.innerText || '')).replace(/ /g, ' ').trim().toLowerCase();
              if (!val) continue;
              if (val.indexOf(wanted) < 0 && val.indexOf(wantedPad) < 0 && val.indexOf(hh24) < 0) continue;
              const hasPm = pmK.some((k) => val.indexOf(k) >= 0);
              const hasAm = amK.some((k) => val.indexOf(k) >= 0);
              if ((job.isPm && (hasPm || !hasAm)) || (!job.isPm && (hasAm || !hasPm))) {
                await clickEl(o); picked = true; await sleep(400); break;
              }
            }
            if (!picked) await sleep(250);
          }
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
    } catch (e) {}
  }

  // Submit (never in test/dry mode - real submissions only on Micheal's explicit taps).
  clickEl(await xpFirst(page, SUBMIT_X, 12000));
  await sleep(3000);
  const state = await page.evaluate(() => {
    const t = (document.body && document.body.innerText) || '';
    return {
      text: t.slice(0, 400),
      done: /تم تسجيل ردك|response has been recorded|إرسال رد آخر|Submit another|تم حفظ/i.test(t),
      required: /مطلوب|required/i.test(t)
    };
  });
  if (state.done) return { ok: true, submitted: true };
  return {
    ok: false,
    error: state.required ? 'validation_blocked' : 'did_not_advance',
    submitted: false,
    detail: state.text.slice(0, 300)
  };
}

module.exports = { runFormWalk };
