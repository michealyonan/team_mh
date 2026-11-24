// team_mh Google Forms relay v5 - cookie-authenticated, verbatim hidden-input replay.
// The gate crack: Google only advances the multi-page flow on the session-scoped
// /forms/u/0/d/e/.../formResponse endpoint when every hidden input from each page's
// HTML (fbzx, fvv, pageHistory, partialResponse, submissionTimestamp, tag, token) is
// replayed verbatim, with continue=1 + emailAddress + radio sentinels on nav posts.
// Deploy as Web App (execute as: Me, access: Anyone) under the deltalogistics work account.
// Script Properties (never in source):
//   FORM_RELAY_SECRET - shared gate secret with the Cloudflare Worker
//   RELAY_COOKIE_GENERAL - full Cookie header of the deltalogistics Google session (general form)
//   RELAY_COOKIE_ALEX - full Cookie header of the alexlogistics Google session (Alexandria form)
// Cookie refresh: POST {"secret":..., "action":"set_cookie", "which":"general"|"alex", "cookie":"..."}
const SECRET = PropertiesService.getScriptProperties().getProperty('FORM_RELAY_SECRET');
const FORMS = {
  '1FAIpQLSekxaUQPgiWq-Y_IPfsTx7wTANA324a2JklFJZ_Gxg9CGPaKA': {
    prop: 'RELAY_COOKIE_GENERAL',
    email: 'deltalogistics.teammh1@gmail.com',
    page0: ['entry.302135773'],
    page1: ['entry.1941659317'],
    radios: ['entry.302135773']
  },
  '1FAIpQLSffSwyTh0w4AYjTU9AG-kj-0UfJHcSTSYnR1DrWJ_h8iPYm3Q': {
    prop: 'RELAY_COOKIE_ALEX',
    email: 'alexlogistics.teammh101@gmail.com',
    page0: ['entry.1976663790'],
    page1: ['entry.186608000', 'entry.2117629487'],
    radios: ['entry.1976663790']
  }
};
function hiddens_(html) {
  const o = {}; const re = /<input type="hidden" name="([^"]+)" value="([^"]*)"/g; let m;
  while ((m = re.exec(html))) o[m[1]] = m[2].replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&#39;/g, "'");
  return o;
}
function doPost(e) {
  const out = (o) => ContentService.createTextOutput(JSON.stringify(o)).setMimeType(ContentService.MimeType.JSON);
  try {
    const body = JSON.parse(e.postData.contents || '{}');
    if (!SECRET || body.secret !== SECRET) return out({ error: 'unauthorized' });
    const props = PropertiesService.getScriptProperties();
    if (body.action === 'set_cookie') {
      const key = body.which === 'alex' ? 'RELAY_COOKIE_ALEX' : body.which === 'general' ? 'RELAY_COOKIE_GENERAL' : '';
      if (!key || typeof body.cookie !== 'string' || body.cookie.length < 100 || body.cookie.length > 8000 || /[\r\n]/.test(body.cookie)) return out({ error: 'bad_cookie' });
      props.setProperty(key, body.cookie);
      return out({ ok: true, set: key });
    }
    const cfg = FORMS[body.formId];
    if (!cfg) return out({ error: 'form_not_allowed' });
    if (!body.fields || typeof body.fields !== 'object' || Object.keys(body.fields).some(k => !/^entry\.\d+(?:_hour|_minute)?$/.test(k))) return out({ error: 'invalid_fields' });
    const cookie = props.getProperty(cfg.prop);
    if (!cookie) return out({ error: 'auth_expired', detail: 'no_cookie' });
    const headers = { Cookie: cookie, 'Accept-Language': 'ar' };
    const base = 'https://docs.google.com/forms/u/0/d/e/' + body.formId + '/';
    const dead = (status, html) => status === 401 || status === 403 || /accounts\.google\.com\/(v3\/signin|ServiceLogin)/.test(html || '');
    const post = (payload) => {
      const resp = UrlFetchApp.fetch(base + 'formResponse', { method: 'post', payload: payload, headers: headers, followRedirects: false, muteHttpExceptions: true });
      return { status: resp.getResponseCode(), html: resp.getContentText() };
    };
    const fields = body.fields;
    const pick = (keys) => { const o = {}; keys.forEach(k => { if (fields[k] !== undefined) o[k] = fields[k]; }); return o; };
    const branchKeys = cfg.page0.concat(cfg.page1);
    const p0 = pick(cfg.page0), p1 = pick(cfg.page1);
    const fin = {};
    Object.keys(fields).forEach(k => { if (branchKeys.indexOf(k) < 0) fin[k] = fields[k]; });
    const isProbe = body.action === 'probe';

    // viewform -> hidden inputs verbatim
    const vf = UrlFetchApp.fetch(base + 'viewform', { headers: headers, muteHttpExceptions: true });
    const vfStatus = vf.getResponseCode();
    const html0 = vf.getContentText();
    if (dead(vfStatus, html0)) return out({ error: 'auth_expired', status: vfStatus });
    const H0 = hiddens_(html0);
    if (!H0.fbzx) return out({ error: 'fbzx_not_found', status: vfStatus });

    // page 0 nav
    const d0 = Object.assign({}, H0, p0, { emailAddress: cfg.email, continue: '1', dlut: String(Date.now()) });
    cfg.radios.forEach(r => { if (p0[r] !== undefined) d0[r + '_sentinel'] = ''; });
    let r = post(d0);
    if (dead(r.status, r.html)) return out({ error: 'auth_expired', status: r.status, step: 0 });
    if (r.status !== 200) return out({ error: 'nav_failed', step: 0, status: r.status });
    const H1 = hiddens_(r.html);
    if (!H1.pageHistory || H1.pageHistory === H0.pageHistory) return out({ error: 'nav_failed', step: 0, status: r.status, detail: 'did_not_advance', pageHistory: H1.pageHistory || '' });

    // page 1 nav
    const d1 = Object.assign({}, H1, p1, { continue: '1', dlut: String(Date.now()) });
    r = post(d1);
    if (dead(r.status, r.html)) return out({ error: 'auth_expired', status: r.status, step: 1 });
    if (r.status !== 200) return out({ error: 'nav_failed', step: 1, status: r.status });
    const H2 = hiddens_(r.html);
    if (!H2.pageHistory || H2.pageHistory === H1.pageHistory) return out({ error: 'nav_failed', step: 1, status: r.status, detail: 'did_not_advance', pageHistory: H2.pageHistory || '' });

    if (isProbe) return out({ ok: true, probe: true, reached: H2.pageHistory, formId: body.formId });

    // final submit: no continue, real submissionTimestamp; Google answers with a
    // redirect to the confirmation page, so follow redirects here (v5 bug: the
    // submission recorded but the 302 stub failed the text check -> false relay_failed)
    const d2 = Object.assign({}, H2, fin, { dlut: String(Date.now()), submissionTimestamp: String(Date.now()) });
    delete d2['continue'];
    const fr = UrlFetchApp.fetch(base + 'formResponse', { method: 'post', payload: d2, headers: headers, followRedirects: true, muteHttpExceptions: true });
    const fStatus = fr.getResponseCode(); const fHtml = fr.getContentText();
    if (dead(fStatus, fHtml)) return out({ error: 'auth_expired', status: fStatus, step: 2 });
    const confirmed = fStatus === 200 && /response has been recorded|تم تسجيل|تم حفظ|إرسال رد آخر|submit another response/i.test(fHtml);
    return out(confirmed ? { ok: true, status: fStatus } : { error: 'submission_unconfirmed', status: fStatus, step: 2, len: fHtml.length });
  } catch (err) { return out({ error: String(err) }); }
}
