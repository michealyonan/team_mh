// team_mh Google Forms relay v4 - cookie-authenticated, full multi-page flow replay.
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
    const headers = { Cookie: cookie };
    const base = 'https://docs.google.com/forms/d/e/' + body.formId + '/';
    const grab = (html, name) => { const m = html.match(new RegExp('name="' + name + '" value="([^"]*)"')); return m ? m[1] : ''; };
    const dead = (status, html) => status === 401 || status === 403 || /accounts\.google\.com\/(v3\/signin|ServiceLogin)/.test(html || '');

    const vf = UrlFetchApp.fetch(base + 'viewform', { headers: headers, muteHttpExceptions: true });
    const vfStatus = vf.getResponseCode();
    const html = vf.getContentText();
    if (dead(vfStatus, html)) return out({ error: 'auth_expired', status: vfStatus });
    let fbzx = grab(html, 'fbzx'), token = grab(html, 'token'), tag = grab(html, 'tag');
    const fvv = grab(html, 'fvv') || '1';
    if (!fbzx) return out({ error: 'fbzx_not_found', status: vfStatus });

    // split worker fields into page0 / page1 / final entries
    const fields = body.fields;
    const pick = (keys) => { const o = {}; keys.forEach(k => { if (fields[k] !== undefined) o[k] = fields[k]; }); return o; };
    const branchKeys = cfg.page0.concat(cfg.page1);
    const p0 = pick(cfg.page0), p1 = pick(cfg.page1);
    const fin = {};
    Object.keys(fields).forEach(k => { if (branchKeys.indexOf(k) < 0) fin[k] = fields[k]; });
    const histParts = (body.pageHistory || '0').split(',');
    const dlut = String(Date.now());

    const post = (entries, pageHistory, partial, submissionTimestamp, isNav, extra) => {
      const payload = Object.assign({}, entries, extra || {});
      cfg.radios.forEach(r => { if (entries[r] !== undefined) payload[r + '_sentinel'] = ''; });
      payload.fbzx = fbzx; payload.fvv = fvv; payload.token = token; payload.tag = tag;
      payload.pageHistory = pageHistory; payload.dlut = dlut;
      payload.submissionTimestamp = submissionTimestamp;
      if (partial !== null) payload.partialResponse = JSON.stringify(partial);
      if (isNav) payload['continue'] = '1';
      const resp = UrlFetchApp.fetch(base + 'formResponse', { method: 'post', payload: payload, headers: headers, followRedirects: false, muteHttpExceptions: true });
      return { status: resp.getResponseCode(), html: resp.getContentText() };
    };

    // step 0 (page 0)
    let r = post(p0, histParts[0] || '0', [null, null, fbzx], '-1', true, { emailAddress: cfg.email });
    if (dead(r.status, r.html)) return out({ error: 'auth_expired', status: r.status, step: 0 });
    if (r.status !== 200) return out({ error: 'nav_failed', step: 0, status: r.status });
    token = grab(r.html, 'token') || token; tag = grab(r.html, 'tag') || tag; fbzx = grab(r.html, 'fbzx') || fbzx;

    // step 1 (page 1)
    const ans0 = cfg.page0.map(k => [null, parseInt(k.split('.')[1], 10), [fields[k]], 0]);
    r = post(p1, histParts.slice(0, 2).join(','), [ans0, null, fbzx, null, null, null, cfg.email, 0], '-1', true);
    if (dead(r.status, r.html)) return out({ error: 'auth_expired', status: r.status, step: 1 });
    if (r.status !== 200) return out({ error: 'nav_failed', step: 1, status: r.status });
    token = grab(r.html, 'token') || token; tag = grab(r.html, 'tag') || tag; fbzx = grab(r.html, 'fbzx') || fbzx;

    // final step
    const ans1 = ans0.concat(cfg.page1.map(k => [null, parseInt(k.split('.')[1], 10), [fields[k]], 0]));
    r = post(fin, body.pageHistory || '0', [ans1, null, fbzx, null, null, null, cfg.email, 0], String(Date.now()), false);
    if (dead(r.status, r.html)) return out({ error: 'auth_expired', status: r.status, step: 2 });
    const confirmed = r.status === 200 && /Your response has been recorded|تم تسجيل ردك|تم تسجيل إجابتك/i.test(r.html) && r.html.length < 60000;
    return out(confirmed ? { ok: true, status: r.status } : { error: 'submission_unconfirmed', status: r.status, step: 2, len: r.html.length });
  } catch (err) { return out({ error: String(err) }); }
}
