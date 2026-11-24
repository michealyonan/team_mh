// team_mh phone form agent v1 - runs inside the app's hidden WebView on docs.google.com.
// Port of relay v8 / worker walkFormDirect: dynamic multi-page walk with verbatim
// hidden-input replay, executed from the phone's own Google session and IP.
// Reads window.__TMH_JOB = {formId, fields, email}; reports via AndroidReport.report(json).
(async function () {
  var R = function (o) { try { AndroidReport.report(JSON.stringify(o)); } catch (e) {} };
  try {
    var job = window.__TMH_JOB;
    if (!job || !job.formId || !job.fields) return R({ error: 'no_job' });
    var formId = job.formId, fields = job.fields, email = job.email || '';
    var base = 'https://docs.google.com/forms/u/0/d/e/' + formId + '/';
    var dead = function (status, html) {
      return status === 401 || status === 403 || /accounts\.google\.com\/(v3\/signin|ServiceLogin|signin)/.test(html || '');
    };
    var hiddens = function (html) {
      var o = {}; var re = /<input type="hidden" name="([^"]+)" value="([^"]*)"/g; var m;
      while ((m = re.exec(html))) o[m[1]] = m[2].replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&#39;/g, "'");
      return o;
    };
    var visible = function (html, b) {
      return html.indexOf('name="' + b + '"') >= 0
        || html.indexOf(b + '_sentinel') >= 0
        || html.indexOf(b + '_hour') >= 0
        || html.indexOf(b + '_minute') >= 0;
    };
    var sleep = function () { return new Promise(function (r) { setTimeout(r, 900 + Math.floor(Math.random() * 800)); }); };
    var HDRS = { 'Accept-Language': 'ar-EG,ar;q=0.9,en;q=0.7' };
    var post = function (data, follow) {
      return fetch(base + 'formResponse', {
        method: 'POST',
        headers: Object.assign({ 'Content-Type': 'application/x-www-form-urlencoded' }, HDRS),
        body: new URLSearchParams(data).toString(),
        redirect: follow ? 'follow' : 'manual',
        credentials: 'same-origin'
      });
    };
    var vf = await fetch(base + 'viewform', { headers: HDRS, credentials: 'same-origin' });
    var html = await vf.text();
    if (dead(vf.status, html)) return R({ error: 'auth_expired', status: vf.status });
    var H = hiddens(html);
    if (!H.fbzx) return R({ error: 'fbzx_not_found', status: vf.status });
    var allKeys = Object.keys(fields);
    var baseOf = function (k) { return k.replace(/_(?:hour|minute)$/, ''); };
    for (var step = 0; step < 12; step++) {
      var here = {};
      allKeys.forEach(function (k) { if (visible(html, baseOf(k))) here[k] = fields[k]; });
      var remaining = allKeys.filter(function (k) { return here[k] === undefined; });
      var last = remaining.length === 0;
      var d = Object.assign({}, H, here, { dlut: String(Date.now()) });
      if (step === 0 && email) d.emailAddress = email;
      if (last) {
        d.submissionTimestamp = String(Date.now());
        delete d['continue'];
        await sleep();
        var fr = await post(d, true);
        var fHtml = await fr.text();
        if (dead(fr.status, fHtml)) return R({ error: 'auth_expired', status: fr.status, step: step });
        var confirmed = fr.status === 200 && /response has been recorded|تم تسجيل|تم حفظ|إرسال رد آخر|submit another response/i.test(fHtml);
        return R(confirmed
          ? { ok: true, status: fr.status, submitted: true }
          : { error: 'submission_unconfirmed', status: fr.status, step: step, submitted: true, len: fHtml.length });
      }
      d['continue'] = '1';
      await sleep();
      var resp = await post(d, false);
      var status = resp.status; html = await resp.text();
      if (dead(status, html)) return R({ error: 'auth_expired', status: status, step: step });
      if (status !== 200) return R({ error: 'nav_failed', step: step, status: status });
      var Hn = hiddens(html);
      if (!Hn.pageHistory || Hn.pageHistory === H.pageHistory) return R({ error: 'nav_failed', step: step, status: status, detail: 'did_not_advance', pageHistory: Hn.pageHistory || '' });
      H = Hn;
    }
    R({ error: 'too_many_pages' });
  } catch (e) {
    R({ error: 'js_exception', detail: String(e).slice(0, 300) });
  }
})();
