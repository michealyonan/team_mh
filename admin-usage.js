/* ☁️ Cloudflare quota tab (admin only) — separate module so index.html stays minimal.
   Data comes from GET /api/admin/usage on the worker (server checks the admin session). */
(function () {
  const PANEL_ID = 'quotaModal';
  let timer = null;

  const el = (id) => document.getElementById(id);
  const fmt = (n) => Number(n || 0).toLocaleString('ar-EG');

  function buildPanel() {
    if (el(PANEL_ID)) return;
    const wrap = document.createElement('div');
    wrap.id = PANEL_ID;
    wrap.style.cssText = 'display:none;position:fixed;inset:0;background:#000c;z-index:78;overflow:auto;padding:12px';
    wrap.onclick = (e) => { if (e.target === wrap) closeQuota(); };
    wrap.innerHTML =
      '<div class="card" style="max-width:520px;margin:auto">' +
        '<div class="row"><h3 style="margin:0">☁️ استهلاك كلاودفلير النهارده</h3>' +
        '<button class="btn pr" id="quotaRefresh" type="button">🔄 تحديث</button>' +
        '<button class="btn" style="margin-inline-start:auto" type="button" id="quotaClose">✕</button></div>' +
        '<div id="quotaSource" class="sub" role="status" style="margin:8px 0"></div>' +
        '<div style="text-align:center;margin:14px 0 4px"><div id="quotaRemaining" style="font-size:44px;font-weight:900;line-height:1.1">—</div>' +
        '<div class="sub" id="quotaRemainingLabel">طلب فاضل من ١٠٠٬٠٠٠ النهارده</div></div>' +
        '<div style="height:14px;border-radius:999px;background:var(--bg,#0f1626);border:1px solid var(--bd,#33415c);overflow:hidden;margin:12px 0 6px">' +
        '<div id="quotaBar" style="height:100%;width:0%;background:linear-gradient(90deg,#22c55e,#f59e0b,#ef4444);transition:width .5s"></div></div>' +
        '<div class="sub" id="quotaUsed" style="text-align:center"></div>' +
        '<div class="sub" id="quotaReset" style="text-align:center;margin-top:8px"></div>' +
        '<div id="quotaStorage" style="margin-top:12px;padding:10px;border:1px solid var(--bd,#33415c);border-radius:10px"></div>' +
        '<div class="sub" id="quotaNote" style="margin-top:10px;line-height:1.8"></div>' +
      '</div>';
    document.body.appendChild(wrap);
    el('quotaClose').onclick = closeQuota;
    el('quotaRefresh').onclick = () => loadQuota(true);
  }

  function render(data) {
    const used = Number(data.used || 0), limit = Number(data.limit || 100000);
    const remaining = Math.max(0, limit - used);
    const pct = Math.min(100, (used / limit) * 100);
    el('quotaRemaining').textContent = fmt(remaining);
    el('quotaRemaining').style.color = pct >= 90 ? '#ef4444' : pct >= 70 ? '#f59e0b' : '#4ade80';
    el('quotaBar').style.width = pct.toFixed(2) + '%';
    el('quotaUsed').textContent = 'المستهلك لحد دلوقتي: ' + fmt(used) + ' طلب (' + fmt(Math.round(pct)) + '٪)';
    const resetAt = new Date(data.reset_at);
    const ms = Math.max(0, resetAt.getTime() - Date.now());
    const hh = Math.floor(ms / 3600000), mm = Math.ceil((ms % 3600000) / 60000);
    const resetCairo = resetAt.toLocaleTimeString('ar-EG', { timeZone: 'Africa/Cairo', hour: 'numeric', minute: '2-digit' });
    el('quotaReset').textContent = 'العداد بيتصفّر الساعة ' + resetCairo + ' بالقاهرة (١٢ منتصف الليل UTC) — فاضل ' + fmt(hh) + ' ساعة و ' + fmt(mm) + ' دقيقة';
    // D1 storage footprint (Micheal 25 Nov): hiring images + auto-delete note.
    const st = el('quotaStorage');
    if (st) {
      if (data.hiring) {
        const mb = (Number(data.hiring.image_bytes || 0) / 1048576);
        const limitMb = Number(data.hiring.d1_db_limit_bytes || 0) / 1048576;
        const pct = limitMb ? Math.min(100, (mb / limitMb) * 100) : 0;
        st.innerHTML = '<div style="font-weight:700;margin-bottom:4px">🗄️ تخزين قاعدة البيانات (D1)</div>' +
          '<div class="sub">صور رفع الاستعلام المحفوظة دلوقتي: ' + fmt(data.hiring.images) + ' صورة (' + fmt(data.hiring.requests) + ' طلب إجمالي) ≈ ' + mb.toFixed(1) + ' ميجا من ' + fmt(limitMb) + ' ميجا (' + pct.toFixed(1) + '٪)</div>' +
          '<div style="height:8px;border-radius:999px;background:var(--bg,#0f1626);border:1px solid var(--bd,#33415c);overflow:hidden;margin:6px 0"><div style="height:100%;width:' + pct.toFixed(2) + '%;background:#22c55e"></div></div>' +
          '<div class="sub" style="color:#4ade80">📦 الصور بتفضل محفوظة مع كل طلب (≈0.5 ميجا للطلب — حوالي 1000 طلب يكفّوا الـ500 ميجا)، ومش بتتمسح غير لما تمسح الطلب بنفسك.</div>';
      } else {
        st.textContent = '';
      }
    }
    if (data.source === 'cloudflare') {
      el('quotaSource').innerHTML = '<span style="color:#4ade80;font-weight:700">✅ رقم حقيقي من Cloudflare لكل الحساب</span>';
      el('quotaNote').textContent = 'الرقم ده جاي مباشرة من كلاودفلير وبيشمل كل الطلبات على الحساب كله النهارده.';
    } else {
      el('quotaSource').innerHTML = '<span style="color:#f59e0b;font-weight:700">⚠️ تقدير تقريبي — مش الرقم الرسمي</span>';
      el('quotaNote').textContent = (data.cloudflare_error
        ? 'الرقم الحقيقي من Cloudflare مش متاح دلوقتي، فالمعروض تقدير من سيرفر التطبيق نفسه. '
        : 'ده تقدير بيعدّ طلبات التطبيق ده بس، ممكن يقلّ شوية عن الحقيقي ولحد ما يتظبط توكن Cloudflare. ') +
        'الرقم الرسمي لكل الحساب موجود في لوحة كلاودفلير.';
    }
  }

  async function loadQuota(manual) {
    const src = el('quotaSource'), btn = el('quotaRefresh');
    if (btn) btn.disabled = true;
    if (manual && src) src.textContent = '⏳ جارٍ التحديث…';
    try {
      const data = await api('/api/admin/usage');
      render(data);
    } catch (e) {
      if (src) src.innerHTML = '<span style="color:#f87171;font-weight:700">⚠️ ' + (e && e.status === 401 ? 'سجّل دخولك بحساب الأدمن الأول' : 'تعذّر تحميل الاستهلاك: ' + (e && e.message || 'خطأ غير معروف')) + '</span>';
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  function closeQuota() {
    if (timer) { clearInterval(timer); timer = null; }
    const p = el(PANEL_ID);
    if (p) p.style.display = 'none';
  }

  window.openQuota = function () {
    buildPanel();
    el(PANEL_ID).style.display = '';
    if (timer) clearInterval(timer);
    timer = setInterval(() => loadQuota(false), 60000);
    loadQuota(false);
  };
  window.closeQuota = closeQuota;
})();
