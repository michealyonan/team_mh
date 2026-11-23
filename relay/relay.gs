// team_mh Google Forms relay - deploy as Web App (execute as: Me, access: Anyone) under each work account.
// Manifest scopes needed: https://www.googleapis.com/auth/forms + https://www.googleapis.com/auth/script.external_request
// Set FORM_RELAY_SECRET in this project's Script Properties, never in source.
const SECRET = PropertiesService.getScriptProperties().getProperty('FORM_RELAY_SECRET');
function doPost(e) {
  const out = (o) => ContentService.createTextOutput(JSON.stringify(o)).setMimeType(ContentService.MimeType.JSON);
  try {
    const body = JSON.parse(e.postData.contents || '{}');
    if (!SECRET || body.secret !== SECRET) return out({ error: 'unauthorized' });
    const allowed = ['1FAIpQLSffSwyTh0w4AYjTU9AG-kj-0UfJHcSTSYnR1DrWJ_h8iPYm3Q', '1FAIpQLSekxaUQPgiWq-Y_IPfsTx7wTANA324a2JklFJZ_Gxg9CGPaKA'];
    if (allowed.indexOf(body.formId) < 0) return out({ error: 'form_not_allowed' });
    if (!body.fields || typeof body.fields !== 'object' || Object.keys(body.fields).some(k => !/^entry\.\d+(?:_hour|_minute)?$/.test(k))) return out({ error: 'invalid_fields' });
    const token = ScriptApp.getOAuthToken();
    const vf = UrlFetchApp.fetch('https://docs.google.com/forms/d/e/' + body.formId + '/viewform', { headers: { Authorization: 'Bearer ' + token }, muteHttpExceptions: true });
    const html = vf.getContentText();
    const m = html.match(/name="fbzx" value="([^"]+)"/);
    if (!m) return out({ error: 'fbzx_not_found', status: vf.getResponseCode() });
    const payload = Object.assign({}, body.fields, { fbzx: m[1], pageHistory: body.pageHistory || '0' });
    const resp = UrlFetchApp.fetch('https://docs.google.com/forms/d/e/' + body.formId + '/formResponse', { method: 'post', payload: payload, headers: { Authorization: 'Bearer ' + token }, followRedirects: false, muteHttpExceptions: true });
    const status = resp.getResponseCode();
    const confirmation = resp.getContentText();
    const confirmed = status === 200 && /Your response has been recorded|تم تسجيل ردك|تم تسجيل إجابتك/i.test(confirmation) && !/accounts\.google\.com\/ServiceLogin|تم رفض الدخول/i.test(confirmation);
    return out(confirmed ? { ok: true, status: status } : { error: 'submission_unconfirmed', status: status });
  } catch (err) { return out({ error: String(err) }); }
}
