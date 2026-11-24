// team_mh Google Forms relay v2 - cookie-authenticated.
// Deploy as Web App (execute as: Me, access: Anyone) under the deltalogistics work account.
// Script Properties (never in source):
//   FORM_RELAY_SECRET - shared gate secret with the Cloudflare Worker
//   RELAY_COOKIE_GENERAL - full Cookie header of the deltalogistics Google session (general form)
//   RELAY_COOKIE_ALEX - full Cookie header of the alexlogistics Google session (Alexandria form)
// Cookie refresh: POST {"secret":..., "action":"set_cookie", "which":"general"|"alex", "cookie":"..."}
const SECRET = PropertiesService.getScriptProperties().getProperty('FORM_RELAY_SECRET');
const FORMS = {
  '1FAIpQLSekxaUQPgiWq-Y_IPfsTx7wTANA324a2JklFJZ_Gxg9CGPaKA': 'RELAY_COOKIE_GENERAL',
  '1FAIpQLSffSwyTh0w4AYjTU9AG-kj-0UfJHcSTSYnR1DrWJ_h8iPYm3Q': 'RELAY_COOKIE_ALEX'
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
    const propKey = FORMS[body.formId];
    if (!propKey) return out({ error: 'form_not_allowed' });
    if (!body.fields || typeof body.fields !== 'object' || Object.keys(body.fields).some(k => !/^entry\.\d+(?:_hour|_minute)?$/.test(k))) return out({ error: 'invalid_fields' });
    const cookie = props.getProperty(propKey);
    if (!cookie) return out({ error: 'auth_expired', detail: 'no_cookie' });
    const headers = { Cookie: cookie };
    const vf = UrlFetchApp.fetch('https://docs.google.com/forms/d/e/' + body.formId + '/viewform', { headers: headers, muteHttpExceptions: true });
    const vfStatus = vf.getResponseCode();
    const html = vf.getContentText();
    if (vfStatus === 401 || vfStatus === 403 || /accounts\.google\.com\/(v3\/signin|ServiceLogin)/.test(html)) return out({ error: 'auth_expired', status: vfStatus });
    const m = html.match(/name="fbzx" value="([^"]+)"/);
    if (!m) return out({ error: 'fbzx_not_found', status: vfStatus });
    const payload = Object.assign({}, body.fields, { fbzx: m[1], pageHistory: body.pageHistory || '0' });
    const resp = UrlFetchApp.fetch('https://docs.google.com/forms/d/e/' + body.formId + '/formResponse', { method: 'post', payload: payload, headers: headers, followRedirects: false, muteHttpExceptions: true });
    const status = resp.getResponseCode();
    const confirmation = resp.getContentText();
    if (status === 401 || status === 403 || /accounts\.google\.com\/(v3\/signin|ServiceLogin)/.test(confirmation)) return out({ error: 'auth_expired', status: status });
    const confirmed = status === 200 && /Your response has been recorded|تم تسجيل ردك|تم تسجيل إجابتك/i.test(confirmation);
    return out(confirmed ? { ok: true, status: status } : { error: 'submission_unconfirmed', status: status });
  } catch (err) { return out({ error: String(err) }); }
}
