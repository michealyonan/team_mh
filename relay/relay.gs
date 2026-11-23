// team_mh Google Forms relay - deploy as Web App (execute as: Me, access: Anyone) under each work account.
// Manifest scopes needed: https://www.googleapis.com/auth/forms + https://www.googleapis.com/auth/script.external_request
const SECRET = '0b51122c0dbb84f4cc243086340194e13f24011456c41b81a1bd924daad64e91';
function doPost(e) {
  const out = (o) => ContentService.createTextOutput(JSON.stringify(o)).setMimeType(ContentService.MimeType.JSON);
  try {
    const body = JSON.parse(e.postData.contents || '{}');
    if (body.secret !== SECRET) return out({ error: 'unauthorized' });
    const token = ScriptApp.getOAuthToken();
    const vf = UrlFetchApp.fetch('https://docs.google.com/forms/d/e/' + body.formId + '/viewform', { headers: { Authorization: 'Bearer ' + token }, muteHttpExceptions: true });
    const html = vf.getContentText();
    const m = html.match(/name="fbzx" value="([^"]+)"/);
    if (!m) return out({ error: 'fbzx_not_found', status: vf.getResponseCode() });
    const payload = Object.assign({}, body.fields, { fbzx: m[1], pageHistory: body.pageHistory || '0' });
    const resp = UrlFetchApp.fetch('https://docs.google.com/forms/d/e/' + body.formId + '/formResponse', { method: 'post', payload: payload, headers: { Authorization: 'Bearer ' + token }, followRedirects: false, muteHttpExceptions: true });
    return out({ status: resp.getResponseCode() });
  } catch (err) { return out({ error: String(err) }); }
}
