// team_mh desktop v0.3.0 - Google Forms walk inside REAL Chrome (puppeteer-core).
// Click-for-click port of Micheal's proven Python tool (process_request /
// process_request_alex / select_time_option_smart) - same step order, same XPaths,
// same Arabic labels. Runs as one in-page async function via page.evaluate.

// The whole walk, self-contained (serialized into the page).
async function walkInPage(job) {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const xp = (s) => {
    try { return document.evaluate(s, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue; } catch (e) { return null; }
  };
  const xpa = (s) => {
    const out = [];
    try {
      const it = document.evaluate(s, document, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
      for (let i = 0; i < it.snapshotLength; i++) out.push(it.snapshotItem(i));
    } catch (e) {}
    return out;
  };
  const clickEl = (el) => {
    if (!el) throw new Error('click: no element');
    try { el.scrollIntoView({ block: 'center' }); } catch (e) {}
    el.click();
  };
  const waitXp = async (s, ms) => {
    const t0 = Date.now();
    while (Date.now() - t0 < ms) {
      const el = xp(s);
      if (el) return el;
      await sleep(300);
    }
    throw new Error('timeout waiting ' + s.slice(0, 60));
  };
  const waitInputs = async (s, ms) => {
    const t0 = Date.now();
    while (Date.now() - t0 < ms) {
      const els = xpa(s);
      if (els.length) return els;
      await sleep(300);
    }
    throw new Error('timeout waiting inputs ' + s.slice(0, 60));
  };
  const typeIn = async (el, text) => {
    el.scrollIntoView({ block: 'center' });
    el.focus();
    el.value = '';
    el.dispatchEvent(new Event('input', { bubbles: true }));
    await sleep(80);
    try { document.execCommand('insertText', false, String(text)); }
    catch (e) { el.value = String(text); el.dispatchEvent(new Event('input', { bubbles: true })); }
    await sleep(120);
  };

  const NEXT = "//span[contains(text(), 'التالي') or contains(text(), 'Next')]";
  const SUBMIT = "//span[contains(text(), 'إرسال') or contains(text(), 'Submit')]";
  const isBreak = job.action === 'break';

  // Step 0: tick the Record-email consent checkbox if present and unchecked (pyw parity).
  try {
    const cb = xp("//div[@role='checkbox']");
    if (cb && cb.getAttribute('aria-checked') !== 'true') { clickEl(cb); await sleep(500); }
  } catch (e) {}

  clickEl(await waitXp("//span[contains(text(), 'شيفتات الطيارين')]", 20000));
  await sleep(500);
  clickEl(await waitXp(NEXT, 12000));
  await sleep(1500);

  if (job.isAlex) {
    // ---- Alexandria flow (process_request_alex) ----
    const inputsPg2 = await waitInputs("//input[@type='text']", 12000);
    await typeIn(inputsPg2[0], job.riderId);
    await sleep(300);
    if (isBreak) clickEl(await waitXp("//span[contains(text(), 'البريكات')]", 12000));
    else clickEl(await waitXp("//span[contains(text(), 'تزويدات شيفتات الطيارين')]", 12000));
    await sleep(500);
    clickEl(await waitXp(NEXT, 12000));
    await sleep(1500);

    if (isBreak) {
      try { clickEl(await waitXp("//span[contains(text(), 'فك بريك')]", 9000)); await sleep(300); } catch (e) {}
      // Reason: best effort (the Python tool proves the walk succeeds without it,
      // but if a reason field/option is visible we fill it).
      if (job.reason) {
        try {
          const ins = xpa("//input[@type='text']").filter((i) => !i.value);
          if (ins.length) await typeIn(ins[0], job.reason);
        } catch (e) {}
        try { const r = xp("//span[contains(text(), '" + job.reason + "')]"); if (r) clickEl(r); } catch (e) {}
      }
    } else {
      // Extend: fill HH / MM then pick AM/PM from the listbox (pyw Alex extend).
      try {
        const tins = xpa("//input[@type='text' or @type='number']");
        if (tins.length >= 2) { await typeIn(tins[0], job.hh12); await typeIn(tins[1], job.mm); await sleep(300); }
        const lb = xp("//div[@role='listbox']");
        if (lb) {
          clickEl(lb);
          const optX = job.isPm
            ? "//div[@role='option']//span[contains(text(), 'مساء') or contains(text(), 'PM') or contains(text(), 'م')]"
            : "//div[@role='option']//span[contains(text(), 'صباح') or contains(text(), 'AM') or contains(text(), 'ص')]";
          clickEl(await waitXp(optX, 12000));
          await sleep(300);
        }
      } catch (e) {}
    }
  } else {
    // ---- Delta cities flow (process_request) ----
    clickEl(await waitXp("//div[@role='listbox']", 12000));
    await sleep(1200);
    const optX = isBreak
      ? "//div[@role='option']//span[contains(text(), 'فك بريك')]"
      : "//div[@role='option']//span[contains(text(), 'تزويدات شيفتات الطيارين')]";
    clickEl(await waitXp(optX, 12000));
    await sleep(500);
    clickEl(await waitXp(NEXT, 12000));
    await sleep(1500);

    if (!isBreak) {
      // select_time_option_smart port: pick the "إلى HH:MM ..." option from the last listbox.
      try {
        const lbs = xpa("//div[@role='listbox']");
        if (lbs.length) {
          const lb = lbs[lbs.length - 1];
          try { lb.scrollIntoView({ block: 'center' }); } catch (e) {}
          await sleep(400);
          clickEl(lb);
          await sleep(1500);
          const wantedH = String(job.hh12).replace(/^0/, '');
          const wanted = wantedH + ':' + job.mm;
          const wantedPad = (job.hh12.length === 1 ? '0' + job.hh12 : job.hh12) + ':' + job.mm;
          const hh24 = job.hh24 + ':' + job.mm;
          const pmK = ['مساء', 'بليل', 'الظهر', 'العصر', 'pm', 'م'];
          const amK = ['صباح', 'الصبح', 'الفجر', 'am', 'ص'];
          let picked = false;
          for (let pass = 0; pass < 30 && !picked; pass++) {
            const opts = xpa("//div[@role='option']");
            for (const o of opts) {
              const val = String(o.getAttribute('data-value') || o.innerText || '').replace(/ /g, ' ').trim().toLowerCase();
              if (!val) continue;
              if (val.indexOf(wanted) < 0 && val.indexOf(wantedPad) < 0 && val.indexOf(hh24) < 0) continue;
              const hasPm = pmK.some((k) => val.indexOf(k) >= 0);
              const hasAm = amK.some((k) => val.indexOf(k) >= 0);
              if ((job.isPm && (hasPm || !hasAm)) || (!job.isPm && (hasAm || !hasPm))) {
                clickEl(o); picked = true; await sleep(400); break;
              }
            }
            if (!picked) await sleep(250);
          }
        }
      } catch (e) {}
    }

    // Rider + city text inputs (pyw: last two inputs, or the single one).
    try {
      const tins = await waitInputs("//input[@type='text']", 9000);
      if (tins.length === 1) { await typeIn(tins[0], job.riderId); }
      else if (tins.length >= 2) {
        await typeIn(tins[tins.length - 2], job.riderId);
        await typeIn(tins[tins.length - 1], job.cityVal);
      }
    } catch (e) {}
  }

  // Submit (never in test/dry mode - real submissions only on Micheal's explicit taps).
  clickEl(await waitXp(SUBMIT, 12000));
  await sleep(3000);
  const txt = (document.body && document.body.innerText) || '';
  const done = /تم تسجيل ردك|response has been recorded|إرسال رد آخر|Submit another|تم حفظ/i.test(txt);
  return done
    ? { ok: true, submitted: true }
    : { ok: false, error: 'did_not_advance', submitted: false, detail: txt.slice(0, 300) };
}

async function runFormWalk(page, job) {
  return page.evaluate(walkInPage, job);
}

module.exports = { runFormWalk, walkInPage };
