'use strict';

const state = {
  csrf: null,
  stats: null,
  charts: {},
  minus2Page: 1,
};

const $ = (id) => document.getElementById(id);

function fmtNum(n) {
  return new Intl.NumberFormat('en-US').format(n ?? 0);
}

async function api(path, options = {}) {
  const opts = Object.assign({ credentials: 'same-origin' }, options);
  opts.headers = Object.assign({}, opts.headers);
  if (opts.body && !(opts.body instanceof FormData)) {
    opts.headers['Content-Type'] = 'application/json';
  }
  if (options.method === 'POST' && state.csrf) {
    opts.headers['X-Admin-CSRF'] = state.csrf;
  }
  const res = await fetch(path, opts);
  let data = null;
  try { data = await res.json(); } catch (e) { /* non-JSON response */ }
  if (!res.ok) {
    const msg = (data && data.error) ? data.error : ('HTTP ' + res.status);
    throw new Error(msg);
  }
  return data;
}

// ---------------------------------------------------------------- Auth ----

async function checkSession() {
  try {
    const data = await api('admin_session.php');
    if (data.authenticated) {
      state.csrf = data.csrf;
      showDashboard();
      return;
    }
  } catch (e) { /* fall through to login */ }
  showLogin();
}

function showLogin() {
  $('loginScreen').hidden = false;
  $('dashboard').hidden = true;
}

function showDashboard() {
  $('loginScreen').hidden = true;
  $('dashboard').hidden = false;
  refreshAll();
  startAutoRefresh();
  loadBannedList();
  searchMinus2(1);
}

$('loginForm').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  $('loginError').hidden = true;
  const password = $('loginPassword').value;
  try {
    const data = await api('admin_login.php', { method: 'POST', body: JSON.stringify({ password }) });
    state.csrf = data.csrf;
    $('loginPassword').value = '';
    showDashboard();
  } catch (e) {
    $('loginError').textContent = e.message || 'ورود ناموفق بود.';
    $('loginError').hidden = false;
  }
});

$('logoutBtn').addEventListener('click', async () => {
  try { await api('admin_logout.php'); } catch (e) { /* ignore */ }
  state.csrf = null;
  showLogin();
});

// ------------------------------------------------------------- Refresh ----

let autoRefreshTimer = null;
function startAutoRefresh() {
  if (autoRefreshTimer) clearInterval(autoRefreshTimer);
  autoRefreshTimer = setInterval(refreshAll, 60 * 1000);
}

$('refreshBtn').addEventListener('click', refreshAll);
$('windowDays').addEventListener('change', refreshAll);

async function refreshAll() {
  const days = $('windowDays').value;
  try {
    const data = await api(`admin_stats.php?days=${encodeURIComponent(days)}&growth_days=365`);
    state.stats = data;
    renderSummary(data);
    renderGrowthChart();
    renderOsChart();
    renderLoadChart(data.server_load_last_hour);
    $('lastUpdated').textContent = 'آخرین بروزرسانی: ' + new Date().toLocaleTimeString('fa-IR');
  } catch (e) {
    if (String(e.message).includes('Not authenticated') || String(e.message).includes('Session expired')) {
      showLogin();
      return;
    }
    $('lastUpdated').textContent = 'خطا در بروزرسانی: ' + e.message;
  }
}

// ------------------------------------------------------------- Summary ----

function renderSummary(data) {
  const s = data.summary;
  const p = s.percentages;
  const cards = [
    ['کاربران رایگان فعال', s.free_active_window, `${p.free_of_active}% از کل فعال`],
    ['کاربران پریمیوم فعال', s.premium_active_window, `${p.premium_of_active}% از کل فعال`],
    ['مجموع فعال در بازه', s.total_active_window, ''],
    ['رایگان جدید (۲۴ساعت)', s.free_new_24h, ''],
    ['پریمیوم جدید (۲۴ساعت)', s.premium_new_24h, ''],
    ['جمع جدید (۲۴ساعت)', s.total_new_24h, ''],
    ['رایگان جدید (۷روز)', s.free_new_7d, ''],
    ['پریمیوم جدید (۷روز)', s.premium_new_7d, ''],
    ['جمع جدید (۷روز)', s.total_new_7d, ''],
    ['کل کاربران رایگان (همه زمان‌ها)', s.free_ever_total, `${p.free_of_ever}% از کل`],
    ['کل کاربران پریمیوم (همه زمان‌ها)', s.premium_ever_total, `${p.premium_of_ever}% از کل`],
    ['کل کاربران (همه زمان‌ها)', s.ever_total, ''],
    ['کاربران غیرفعال (همه زمان‌ها)', s.inactive_ever_total, `${p.inactive_of_ever}% از کل`],
  ];
  $('summaryCards').innerHTML = cards.map(([label, value, sub]) => `
    <div class="card">
      <div class="label">${label}</div>
      <div class="value">${fmtNum(value)}</div>
      ${sub ? `<div class="sub">${sub}</div>` : ''}
    </div>
  `).join('');
}

// --------------------------------------------------------- Growth chart ---

function bucketGrowth(daily, granularity) {
  const buckets = new Map();
  for (const row of daily) {
    const d = new Date(row.date + 'T00:00:00Z');
    let key;
    if (granularity === 'day') {
      key = row.date;
    } else if (granularity === 'week') {
      const onejan = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
      const week = Math.ceil((((d - onejan) / 86400000) + onejan.getUTCDay() + 1) / 7);
      key = `${d.getUTCFullYear()}-W${String(week).padStart(2, '0')}`;
    } else {
      key = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
    }
    if (!buckets.has(key)) buckets.set(key, { free_new: 0, premium_new: 0, free_cumulative: row.free_cumulative, premium_cumulative: row.premium_cumulative });
    const b = buckets.get(key);
    b.free_new += row.free_new;
    b.premium_new += row.premium_new;
    b.free_cumulative = row.free_cumulative;
    b.premium_cumulative = row.premium_cumulative;
  }
  return buckets;
}

function renderGrowthChart() {
  if (!state.stats) return;
  const granularity = $('growthGranularity').value;
  const metric = $('growthMetric').value;
  const buckets = bucketGrowth(state.stats.growth_daily, granularity);
  const labels = Array.from(buckets.keys());
  const freeKey = metric === 'new' ? 'free_new' : 'free_cumulative';
  const premiumKey = metric === 'new' ? 'premium_new' : 'premium_cumulative';
  const freeData = labels.map((k) => buckets.get(k)[freeKey]);
  const premiumData = labels.map((k) => buckets.get(k)[premiumKey]);

  const ctx = $('growthChart').getContext('2d');
  if (state.charts.growth) state.charts.growth.destroy();
  state.charts.growth = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        { label: 'رایگان', data: freeData, borderColor: '#4aa3ff', backgroundColor: 'rgba(74,163,255,0.15)', tension: 0.25, fill: true },
        { label: 'پریمیوم', data: premiumData, borderColor: '#22c594', backgroundColor: 'rgba(34,197,148,0.15)', tension: 0.25, fill: true },
      ],
    },
    options: chartBaseOptions(),
  });
}

$('growthGranularity').addEventListener('change', renderGrowthChart);
$('growthMetric').addEventListener('change', renderGrowthChart);

// ------------------------------------------------------------- OS chart ---

function renderOsChart() {
  if (!state.stats) return;
  const segment = $('osSegment').value;
  const rows = state.stats.by_os;
  const labels = rows.map((r) => r.platform);
  const data = rows.map((r) => r[segment]);

  const ctx = $('osChart').getContext('2d');
  if (state.charts.os) state.charts.os.destroy();
  state.charts.os = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{ label: 'کاربران فعال', data, backgroundColor: '#4aa3ff' }],
    },
    options: chartBaseOptions(),
  });
}

$('osSegment').addEventListener('change', renderOsChart);

// ----------------------------------------------------------- Load chart ---

function renderLoadChart(series) {
  const labels = (series || []).map((r) => r.minute);
  const data = (series || []).map((r) => r.requests);
  const ctx = $('loadChart').getContext('2d');
  if (state.charts.load) state.charts.load.destroy();
  state.charts.load = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{ label: 'درخواست در دقیقه', data, borderColor: '#e5484d', backgroundColor: 'rgba(229,72,77,0.15)', tension: 0.2, fill: true }],
    },
    options: chartBaseOptions(),
  });
}

function chartBaseOptions() {
  return {
    responsive: true,
    plugins: { legend: { labels: { color: '#e6edf3' } } },
    scales: {
      x: { ticks: { color: '#8a99a8' }, grid: { color: '#1f2a36' } },
      y: { ticks: { color: '#8a99a8' }, grid: { color: '#1f2a36' }, beginAtZero: true },
    },
  };
}

// --------------------------------------------------------- Search / ban ---

$('searchBtn').addEventListener('click', runSearch);
$('searchInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') runSearch(); });

async function runSearch() {
  const q = $('searchInput').value.trim();
  const box = $('searchResults');
  if (!q) { box.innerHTML = ''; return; }
  box.innerHTML = '<div class="empty-state">در حال جستجو...</div>';
  try {
    const data = await api(`admin_search.php?q=${encodeURIComponent(q)}`);
    renderSearchResults(data);
  } catch (e) {
    box.innerHTML = `<div class="empty-state">خطا: ${e.message}</div>`;
  }
}

function renderSearchResults(data) {
  const box = $('searchResults');
  const rowsHtml = [];

  if (data.licenses && data.licenses.length) {
    rowsHtml.push('<h3 class="small muted">لایسنس‌های پریمیوم</h3>');
    rowsHtml.push('<div class="table-wrap"><table><thead><tr>' +
      '<th>ایمیل</th><th>محصول</th><th>سیستم‌عامل</th><th>وضعیت</th><th>آخرین مشاهده</th><th>بن</th><th></th>' +
      '</tr></thead><tbody>');
    for (const r of data.licenses) {
      rowsHtml.push(`<tr>
        <td>${escapeHtml(r.user_email)}</td>
        <td>${escapeHtml(r.product_name)}</td>
        <td>${escapeHtml(r.device_type)}</td>
        <td>${escapeHtml(r.status)}</td>
        <td>${escapeHtml(r.last_seen_at || '-')}</td>
        <td>${r.banned ? '<span class="badge banned">بن‌شده</span>' : '<span class="badge ok">آزاد</span>'}</td>
        <td><button class="btn small ${r.banned ? '' : 'danger'}" data-ban-license="${r.id}" data-action="${r.banned ? 'unban' : 'ban'}">${r.banned ? 'آزاد کردن' : 'بن کردن'}</button></td>
      </tr>`);
    }
    rowsHtml.push('</tbody></table></div>');
  }

  if (data.free_devices && data.free_devices.length) {
    rowsHtml.push('<h3 class="small muted">نصب‌های رایگان</h3>');
    rowsHtml.push('<div class="table-wrap"><table><thead><tr>' +
      '<th>machine_id</th><th>سیستم‌عامل</th><th>اولین مشاهده</th><th>آخرین مشاهده</th><th>بن</th><th></th>' +
      '</tr></thead><tbody>');
    for (const r of data.free_devices) {
      rowsHtml.push(`<tr>
        <td>${escapeHtml((r.machine_id || '').slice(0, 16))}…</td>
        <td>${escapeHtml(r.platform_profile || '-')}</td>
        <td>${escapeHtml(r.first_seen_at || '-')}</td>
        <td>${escapeHtml(r.last_seen_at || '-')}</td>
        <td>${r.banned ? '<span class="badge banned">بن‌شده</span>' : '<span class="badge ok">آزاد</span>'}</td>
        <td><button class="btn small ${r.banned ? '' : 'danger'}" data-ban-free="${escapeHtml(r.machine_id || '')}" data-device-hash="${escapeHtml(r.device_public_key_hash || '')}" data-action="${r.banned ? 'unban' : 'ban'}">${r.banned ? 'آزاد کردن' : 'بن کردن'}</button></td>
      </tr>`);
    }
    rowsHtml.push('</tbody></table></div>');
  }

  if (!rowsHtml.length) {
    box.innerHTML = '<div class="empty-state">چیزی پیدا نشد.</div>';
    return;
  }
  box.innerHTML = rowsHtml.join('');

  box.querySelectorAll('[data-ban-license]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const licenseId = btn.getAttribute('data-ban-license');
      const action = btn.getAttribute('data-action');
      let reason = null;
      if (action === 'ban') reason = prompt('دلیل بن کردن (اختیاری):') || '';
      try {
        await api('admin_ban.php', { method: 'POST', body: JSON.stringify({ action, scope: 'license', license_id: Number(licenseId), reason }) });
        runSearch();
        loadBannedList();
      } catch (e) { alert('خطا: ' + e.message); }
    });
  });

  box.querySelectorAll('[data-ban-free]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const machineId = btn.getAttribute('data-ban-free');
      const deviceHash = btn.getAttribute('data-device-hash');
      const action = btn.getAttribute('data-action');
      let reason = null;
      if (action === 'ban') reason = prompt('دلیل بن کردن (اختیاری):') || '';
      try {
        await api('admin_ban.php', { method: 'POST', body: JSON.stringify({ action, scope: 'free_device', machine_id: machineId, device_key_hash: deviceHash, reason }) });
        runSearch();
        loadBannedList();
      } catch (e) { alert('خطا: ' + e.message); }
    });
  });
}

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ------------------------------------------------------------- Banned ----

$('refreshBannedBtn').addEventListener('click', loadBannedList);

async function loadBannedList() {
  const box = $('bannedList');
  box.innerHTML = '<div class="empty-state">در حال بارگذاری...</div>';
  try {
    const data = await api('admin_search.php?scope=banned');
    if (!data.banned || !data.banned.length) {
      box.innerHTML = '<div class="empty-state">کسی بن نشده.</div>';
      return;
    }
    const rows = data.banned.map((b) => `<tr>
      <td>${escapeHtml(b.scope)}</td>
      <td>${escapeHtml(b.user_email || '-')}</td>
      <td>${escapeHtml((b.machine_id || '').slice(0, 16))}${b.machine_id ? '…' : '-'}</td>
      <td>${escapeHtml(b.reason || '-')}</td>
      <td>${escapeHtml(b.banned_at)}</td>
      <td><button class="btn small" data-unban="${b.id}" data-scope="${escapeHtml(b.scope)}" data-license="${b.license_id || ''}" data-machine="${escapeHtml(b.machine_id || '')}" data-device="${escapeHtml(b.device_public_key_hash || '')}">آزاد کردن</button></td>
    </tr>`).join('');
    box.innerHTML = `<div class="table-wrap"><table><thead><tr>
      <th>نوع</th><th>ایمیل</th><th>machine_id</th><th>دلیل</th><th>تاریخ بن</th><th></th>
    </tr></thead><tbody>${rows}</tbody></table></div>`;

    box.querySelectorAll('[data-unban]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const scope = btn.getAttribute('data-scope');
        try {
          if (scope === 'license') {
            await api('admin_ban.php', { method: 'POST', body: JSON.stringify({ action: 'unban', scope: 'license', license_id: Number(btn.getAttribute('data-license')) }) });
          } else {
            await api('admin_ban.php', { method: 'POST', body: JSON.stringify({ action: 'unban', scope: 'free_device', machine_id: btn.getAttribute('data-machine'), device_key_hash: btn.getAttribute('data-device') }) });
          }
          loadBannedList();
        } catch (e) { alert('خطا: ' + e.message); }
      });
    });
  } catch (e) {
    box.innerHTML = `<div class="empty-state">خطا: ${e.message}</div>`;
  }
}

// -------------------------------------------------------------- -2 log ---

$('minus2SearchBtn').addEventListener('click', () => searchMinus2(1));
$('minus2Query').addEventListener('keydown', (e) => { if (e.key === 'Enter') searchMinus2(1); });

async function searchMinus2(page) {
  state.minus2Page = page;
  const q = $('minus2Query').value.trim();
  const reason = $('minus2Reason').value;
  const kind = $('minus2Kind').value;
  const box = $('minus2Results');
  box.innerHTML = '<div class="empty-state">در حال جستجو...</div>';
  try {
    const params = new URLSearchParams({ page: String(page), page_size: '50' });
    if (q) params.set('q', q);
    if (reason) params.set('reason_code', reason);
    if (kind) params.set('install_kind', kind);
    const data = await api('admin_minus2.php?' + params.toString());
    renderMinus2(data);
  } catch (e) {
    box.innerHTML = `<div class="empty-state">خطا: ${e.message}</div>`;
  }
}

function renderMinus2(data) {
  const box = $('minus2Results');
  if (!data.rows.length) {
    box.innerHTML = '<div class="empty-state">چیزی پیدا نشد.</div>';
    $('minus2Pager').innerHTML = '';
    return;
  }
  const rows = data.rows.map((r) => `<tr>
    <td>${escapeHtml(r.occurred_at)}</td>
    <td>${escapeHtml(r.install_kind)}</td>
    <td>${escapeHtml(r.reason_code)}</td>
    <td>${escapeHtml(r.user_email || '-')}</td>
    <td>${escapeHtml((r.machine_id || '').slice(0, 16))}${r.machine_id ? '…' : '-'}</td>
    <td>${escapeHtml(r.platform_profile || '-')}</td>
    <td>${escapeHtml(r.reason_detail || '-')}</td>
  </tr>`).join('');
  box.innerHTML = `<div class="table-wrap"><table><thead><tr>
    <th>زمان</th><th>نوع</th><th>علت</th><th>ایمیل</th><th>machine_id</th><th>سیستم‌عامل</th><th>جزئیات</th>
  </tr></thead><tbody>${rows}</tbody></table></div>`;

  const totalPages = Math.max(1, Math.ceil(data.total / data.page_size));
  $('minus2Pager').innerHTML = `
    <button class="btn small" id="minus2Prev" ${data.page <= 1 ? 'disabled' : ''}>قبلی</button>
    <span>صفحه ${data.page} از ${totalPages} (${fmtNum(data.total)} ردیف)</span>
    <button class="btn small" id="minus2Next" ${data.page >= totalPages ? 'disabled' : ''}>بعدی</button>
  `;
  const prevBtn = $('minus2Prev');
  const nextBtn = $('minus2Next');
  if (prevBtn) prevBtn.addEventListener('click', () => searchMinus2(data.page - 1));
  if (nextBtn) nextBtn.addEventListener('click', () => searchMinus2(data.page + 1));
}

// ------------------------------------------------------------- Startup ---

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js').catch(() => {});
}

checkSession();
