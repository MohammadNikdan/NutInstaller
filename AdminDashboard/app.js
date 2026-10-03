'use strict';

// ------------------------------------------------------------------- i18n ---

const DICT = {
  fa: {
    app_title: 'پنل مدیریت Nutricula',
    login_sub: 'برای ادامه رمز عبور را وارد کنید.',
    login_password_placeholder: 'رمز عبور',
    login_submit: 'ورود',
    login_failed: 'ورود ناموفق بود.',

    window_label: 'بازه فعال بودن:',
    window_1d: '۲۴ ساعت',
    window_7d: '۷ روز',
    window_30d: '۳۰ روز',
    window_90d: '۹۰ روز',
    refresh: 'بروزرسانی',
    logout: 'خروج',

    growth_title: 'روند رشد کاربران',
    gran_day: 'روزانه',
    gran_week: 'هفتگی',
    gran_month: 'ماهانه',
    metric_new: 'کاربر جدید',
    metric_cumulative: 'مجموع تجمعی',

    os_title: 'کاربران فعال به تفکیک سیستم‌عامل',
    segment_total: 'همه',
    segment_free: 'رایگان',
    segment_premium: 'پریمیوم',

    load_title: 'شلوغی سرور (درخواست در دقیقه، ۱ ساعت اخیر)',
    conversion_title: 'نرخ تبدیل رایگان به پریمیوم',
    build_title: 'ادوپشن نسخه (build)',
    health_title: 'سلامت و وضعیت کلی',
    suspicious_title: 'IPهای مشکوک',

    search_title: 'جستجوی کاربر / بن کردن',
    search_placeholder: 'ایمیل، machine_id یا device_key_hash یا UUID لایسنس',
    search_btn: 'جستجو',

    banned_title: 'لیست بن‌شده‌ها',
    refresh_list: 'بروزرسانی لیست',

    minus2_title: 'گزارش‌های -۲',
    minus2_placeholder: 'ایمیل یا machine_id',
    minus2_reason_all: 'همه علت‌ها',
    minus2_kind_all: 'رایگان و پریمیوم',
    minus2_kind_free: 'فقط رایگان',
    minus2_kind_premium: 'فقط پریمیوم',

    card_free_active: 'کاربران رایگان فعال',
    card_premium_active: 'کاربران پریمیوم فعال',
    card_total_active: 'مجموع فعال در بازه',
    card_free_new_24h: 'رایگان جدید (۲۴ساعت)',
    card_premium_new_24h: 'پریمیوم جدید (۲۴ساعت)',
    card_total_new_24h: 'جمع جدید (۲۴ساعت)',
    card_free_new_7d: 'رایگان جدید (۷روز)',
    card_premium_new_7d: 'پریمیوم جدید (۷روز)',
    card_total_new_7d: 'جمع جدید (۷روز)',
    card_free_ever: 'کل کاربران رایگان (همه زمان‌ها)',
    card_premium_ever: 'کل کاربران پریمیوم (همه زمان‌ها)',
    card_total_ever: 'کل کاربران (همه زمان‌ها)',
    card_inactive_ever: 'کاربران غیرفعال (همه زمان‌ها)',
    pct_of_active: '{pct}% از کل فعال',
    pct_of_total: '{pct}% از کل',

    label_free: 'رایگان',
    label_premium: 'پریمیوم',
    label_active_users: 'کاربران فعال',
    label_requests_per_min: 'درخواست در دقیقه',

    conv_in_window: 'تبدیل‌شده در بازه انتخابی',
    conv_all_time: 'تبدیل‌شده (کل تاریخچه)',
    pct_of_free: '{pct}% از کل رایگان‌ها',
    conv_avg_days: 'میانگین روز تا تبدیل',

    build_empty: 'هنوز داده‌ای برای نسخه‌ی نصب‌شده ثبت نشده.',
    build_latest_label: 'آخرین نسخه‌ی منتشرشده:',
    build_pct_suffix: '{pct}% از نصب‌های فعال با نسخه‌ی مشخص روی آخرین نسخه‌اند.',
    badge_latest: 'آخرین نسخه',
    th_version: 'نسخه',
    th_free: 'رایگان',
    th_premium: 'پریمیوم',
    th_total: 'جمع',

    health_exp_7d: 'لایسنس‌های نزدیک به انقضا (۷ روز)',
    health_exp_30d: 'لایسنس‌های نزدیک به انقضا (۳۰ روز)',
    health_clone_blocked: 'در حال بلاک کلون (الان)',
    health_token_suspicious: 'هشدار توکن مشکوک (الان)',
    health_verify_rate: 'نرخ موفقیت verify (بازه)',
    health_verify_sub: 'از {n} تلاش',

    susp_volume_title: 'بیشترین حجم درخواست (۲۴ ساعت اخیر)',
    susp_fail_title: 'بیشترین تلاش ناموفق (بازه انتخابی)',
    th_ip: 'IP',
    th_request_count: 'تعداد درخواست',
    th_failed_count: 'تعداد تلاش ناموفق',
    nothing_unusual: 'چیزی غیرعادی دیده نشد.',

    searching: 'در حال جستجو...',
    loading: 'در حال بارگذاری...',
    premium_licenses_title: 'لایسنس‌های پریمیوم',
    free_installs_title: 'نصب‌های رایگان',
    th_email: 'ایمیل',
    th_product: 'محصول',
    th_os: 'سیستم‌عامل',
    th_status: 'وضعیت',
    th_last_seen: 'آخرین مشاهده',
    th_first_seen: 'اولین مشاهده',
    th_ban: 'بن',
    th_machine_id: 'machine_id',
    th_type: 'نوع',
    th_reason: 'دلیل',
    th_ban_date: 'تاریخ بن',
    th_time: 'زمان',
    th_cause: 'علت',
    th_details: 'جزئیات',
    badge_banned: 'بن‌شده',
    badge_free: 'آزاد',
    action_ban: 'بن کردن',
    action_unban: 'آزاد کردن',
    nothing_found: 'چیزی پیدا نشد.',
    nobody_banned: 'کسی بن نشده.',
    ban_reason_prompt: 'دلیل بن کردن (اختیاری):',
    error_prefix: 'خطا: ',
    refresh_error_prefix: 'خطا در بروزرسانی: ',
    last_updated_prefix: 'آخرین بروزرسانی: ',
    prev: 'قبلی',
    next: 'بعدی',
    page_of: 'صفحه {page} از {total} ({rows} ردیف)',
  },

  en: {
    app_title: 'Nutricula Admin Panel',
    login_sub: 'Enter your password to continue.',
    login_password_placeholder: 'Password',
    login_submit: 'Sign in',
    login_failed: 'Sign-in failed.',

    window_label: 'Active window:',
    window_1d: '24 hours',
    window_7d: '7 days',
    window_30d: '30 days',
    window_90d: '90 days',
    refresh: 'Refresh',
    logout: 'Log out',

    growth_title: 'User growth trend',
    gran_day: 'Daily',
    gran_week: 'Weekly',
    gran_month: 'Monthly',
    metric_new: 'New users',
    metric_cumulative: 'Cumulative total',

    os_title: 'Active users by OS',
    segment_total: 'All',
    segment_free: 'Free',
    segment_premium: 'Premium',

    load_title: 'Server load (requests/min, last 1 hour)',
    conversion_title: 'Free-to-premium conversion rate',
    build_title: 'Build adoption',
    health_title: 'Health & overall status',
    suspicious_title: 'Suspicious IPs',

    search_title: 'Search users / ban',
    search_placeholder: 'Email, machine_id, device_key_hash or license UUID',
    search_btn: 'Search',

    banned_title: 'Banned list',
    refresh_list: 'Refresh list',

    minus2_title: '-2 reports',
    minus2_placeholder: 'Email or machine_id',
    minus2_reason_all: 'All reasons',
    minus2_kind_all: 'Free & premium',
    minus2_kind_free: 'Free only',
    minus2_kind_premium: 'Premium only',

    card_free_active: 'Active free users',
    card_premium_active: 'Active premium users',
    card_total_active: 'Total active in window',
    card_free_new_24h: 'New free (24h)',
    card_premium_new_24h: 'New premium (24h)',
    card_total_new_24h: 'Total new (24h)',
    card_free_new_7d: 'New free (7d)',
    card_premium_new_7d: 'New premium (7d)',
    card_total_new_7d: 'Total new (7d)',
    card_free_ever: 'Total free users (all-time)',
    card_premium_ever: 'Total premium users (all-time)',
    card_total_ever: 'Total users (all-time)',
    card_inactive_ever: 'Inactive users (all-time)',
    pct_of_active: '{pct}% of active total',
    pct_of_total: '{pct}% of total',

    label_free: 'Free',
    label_premium: 'Premium',
    label_active_users: 'Active users',
    label_requests_per_min: 'Requests/min',

    conv_in_window: 'Converted in selected window',
    conv_all_time: 'Converted (all-time)',
    pct_of_free: '{pct}% of all free users',
    conv_avg_days: 'Avg. days to convert',

    build_empty: 'No installed-version data recorded yet.',
    build_latest_label: 'Latest published version:',
    build_pct_suffix: '{pct}% of active installs with a known version are on the latest.',
    badge_latest: 'Latest',
    th_version: 'Version',
    th_free: 'Free',
    th_premium: 'Premium',
    th_total: 'Total',

    health_exp_7d: 'Licenses expiring (7 days)',
    health_exp_30d: 'Licenses expiring (30 days)',
    health_clone_blocked: 'Clone-blocked (now)',
    health_token_suspicious: 'Suspicious token alerts (now)',
    health_verify_rate: 'Verify success rate (window)',
    health_verify_sub: 'out of {n} attempts',

    susp_volume_title: 'Top by request volume (last 24h)',
    susp_fail_title: 'Top by failed attempts (selected window)',
    th_ip: 'IP',
    th_request_count: 'Requests',
    th_failed_count: 'Failed attempts',
    nothing_unusual: 'Nothing unusual spotted.',

    searching: 'Searching…',
    loading: 'Loading…',
    premium_licenses_title: 'Premium licenses',
    free_installs_title: 'Free installs',
    th_email: 'Email',
    th_product: 'Product',
    th_os: 'OS',
    th_status: 'Status',
    th_last_seen: 'Last seen',
    th_first_seen: 'First seen',
    th_ban: 'Ban',
    th_machine_id: 'machine_id',
    th_type: 'Type',
    th_reason: 'Reason',
    th_ban_date: 'Ban date',
    th_time: 'Time',
    th_cause: 'Cause',
    th_details: 'Details',
    badge_banned: 'Banned',
    badge_free: 'Free',
    action_ban: 'Ban',
    action_unban: 'Unban',
    nothing_found: 'Nothing found.',
    nobody_banned: 'No one is banned.',
    ban_reason_prompt: 'Ban reason (optional):',
    error_prefix: 'Error: ',
    refresh_error_prefix: 'Refresh error: ',
    last_updated_prefix: 'Last updated: ',
    prev: 'Previous',
    next: 'Next',
    page_of: 'Page {page} of {total} ({rows} rows)',
  },
};

function detectInitialLang() {
  try {
    const saved = localStorage.getItem('nutricula_admin_lang');
    if (saved === 'fa' || saved === 'en') return saved;
  } catch (e) { /* ignore */ }
  return 'fa';
}

const state = {
  csrf: null,
  stats: null,
  charts: {},
  minus2Page: 1,
  lang: detectInitialLang(),
};

const $ = (id) => document.getElementById(id);

function t(key, vars) {
  const dict = DICT[state.lang] || DICT.fa;
  let str = dict[key] ?? DICT.fa[key] ?? key;
  if (vars) {
    for (const k of Object.keys(vars)) {
      str = str.replace(`{${k}}`, vars[k]);
    }
  }
  return str;
}

function fmtNum(n) {
  return new Intl.NumberFormat('en-US').format(n ?? 0);
}

function applyStaticTranslations() {
  document.documentElement.lang = state.lang;
  document.documentElement.dir = state.lang === 'fa' ? 'rtl' : 'ltr';

  document.querySelectorAll('[data-i18n]').forEach((el) => {
    el.textContent = t(el.getAttribute('data-i18n'));
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
    el.setAttribute('placeholder', t(el.getAttribute('data-i18n-placeholder')));
  });
  document.querySelectorAll('[data-lang-btn]').forEach((btn) => {
    btn.classList.toggle('active', btn.getAttribute('data-lang-btn') === state.lang);
  });
}

function setLang(lang) {
  if (lang !== 'fa' && lang !== 'en') return;
  state.lang = lang;
  try { localStorage.setItem('nutricula_admin_lang', lang); } catch (e) { /* ignore */ }
  applyStaticTranslations();
  // Re-render anything already on screen so it picks up the new language.
  if (state.stats) {
    renderSummary(state.stats);
    renderGrowthChart();
    renderOsChart();
    renderLoadChart(state.stats.server_load_last_hour);
    renderConversion(state.stats.conversion);
    renderBuildAdoption(state.stats.build_adoption);
    renderHealth(state.stats.health);
    renderSuspiciousIps(state.stats.suspicious_ips);
  }
  if ($('searchInput') && $('searchInput').value.trim()) runSearch();
  loadBannedList();
  searchMinus2(state.minus2Page || 1);
}

document.querySelectorAll('[data-lang-btn]').forEach((btn) => {
  btn.addEventListener('click', () => setLang(btn.getAttribute('data-lang-btn')));
});

applyStaticTranslations();

// --------------------------------------------------------- Password show ---

const pwdInput = $('loginPassword');
const toggleBtn = $('togglePasswordBtn');
if (toggleBtn && pwdInput) {
  toggleBtn.addEventListener('click', () => {
    const show = pwdInput.type === 'password';
    pwdInput.type = show ? 'text' : 'password';
    $('eyeIcon').hidden = show;
    $('eyeOffIcon').hidden = !show;
  });
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
  $('dashboard').hidden = true;
  $('loginScreen').hidden = false;
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
    $('loginError').textContent = e.message || t('login_failed');
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
    renderConversion(data.conversion);
    renderBuildAdoption(data.build_adoption);
    renderHealth(data.health);
    renderSuspiciousIps(data.suspicious_ips);
    const locale = state.lang === 'fa' ? 'fa-IR' : 'en-US';
    $('lastUpdated').textContent = t('last_updated_prefix') + new Date().toLocaleTimeString(locale);
  } catch (e) {
    if (String(e.message).includes('Not authenticated') || String(e.message).includes('Session expired')) {
      showLogin();
      return;
    }
    $('lastUpdated').textContent = t('refresh_error_prefix') + e.message;
  }
}

// ------------------------------------------------------------- Summary ----

function renderSummary(data) {
  const s = data.summary;
  const p = s.percentages;
  const cards = [
    [t('card_free_active'), s.free_active_window, t('pct_of_active', { pct: p.free_of_active })],
    [t('card_premium_active'), s.premium_active_window, t('pct_of_active', { pct: p.premium_of_active })],
    [t('card_total_active'), s.total_active_window, ''],
    [t('card_free_new_24h'), s.free_new_24h, ''],
    [t('card_premium_new_24h'), s.premium_new_24h, ''],
    [t('card_total_new_24h'), s.total_new_24h, ''],
    [t('card_free_new_7d'), s.free_new_7d, ''],
    [t('card_premium_new_7d'), s.premium_new_7d, ''],
    [t('card_total_new_7d'), s.total_new_7d, ''],
    [t('card_free_ever'), s.free_ever_total, t('pct_of_total', { pct: p.free_of_ever })],
    [t('card_premium_ever'), s.premium_ever_total, t('pct_of_total', { pct: p.premium_of_ever })],
    [t('card_total_ever'), s.ever_total, ''],
    [t('card_inactive_ever'), s.inactive_ever_total, t('pct_of_total', { pct: p.inactive_of_ever })],
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
        { label: t('label_free'), data: freeData, borderColor: '#0f9d73', backgroundColor: 'rgba(15,157,115,0.12)', tension: 0.3, fill: true, borderWidth: 2.5, pointRadius: 0 },
        { label: t('label_premium'), data: premiumData, borderColor: '#b68a2e', backgroundColor: 'rgba(182,138,46,0.12)', tension: 0.3, fill: true, borderWidth: 2.5, pointRadius: 0 },
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
      datasets: [{ label: t('label_active_users'), data, backgroundColor: '#0f9d73', borderRadius: 6, maxBarThickness: 42 }],
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
      datasets: [{ label: t('label_requests_per_min'), data, borderColor: '#d8485a', backgroundColor: 'rgba(216,72,90,0.12)', tension: 0.25, fill: true, borderWidth: 2.5, pointRadius: 0 }],
    },
    options: chartBaseOptions(),
  });
}

function chartBaseOptions() {
  return {
    responsive: true,
    plugins: { legend: { labels: { color: '#43534c', font: { family: getComputedStyle(document.body).fontFamily } } } },
    scales: {
      x: { ticks: { color: '#7a8780' }, grid: { color: 'rgba(23,35,30,0.07)' } },
      y: { ticks: { color: '#7a8780' }, grid: { color: 'rgba(23,35,30,0.07)' }, beginAtZero: true },
    },
  };
}

// ---------------------------------------------------------- Conversion ----

function renderConversion(c) {
  if (!c) return;
  const cards = [
    [t('conv_in_window'), c.converted_in_window, ''],
    [t('conv_all_time'), c.converted_all_time, t('pct_of_free', { pct: c.conversion_rate_all_time_pct })],
    [t('conv_avg_days'), c.avg_days_free_to_premium ?? '-', ''],
  ];
  $('conversionCards').innerHTML = cards.map(([label, value, sub]) => `
    <div class="card">
      <div class="label">${label}</div>
      <div class="value">${typeof value === 'number' ? fmtNum(value) : value}</div>
      ${sub ? `<div class="sub">${sub}</div>` : ''}
    </div>
  `).join('');
}

// ------------------------------------------------------- Build adoption ---

function renderBuildAdoption(b) {
  if (!b) return;
  const box = $('buildAdoption');
  if (!b.rows.length) {
    box.innerHTML = `<div class="empty-state">${t('build_empty')}</div>`;
    return;
  }
  const rows = b.rows.map((r) => `<tr>
    <td>${escapeHtml(r.version)} ${r.is_latest ? `<span class="badge ok">${t('badge_latest')}</span>` : ''}</td>
    <td>${fmtNum(r.free)}</td>
    <td>${fmtNum(r.premium)}</td>
    <td>${fmtNum(r.total)}</td>
  </tr>`).join('');
  box.innerHTML = `
    <div class="sub" style="margin-bottom:10px;">${t('build_latest_label')} <strong>${escapeHtml(b.latest_version || '-')}</strong> — ${t('build_pct_suffix', { pct: b.pct_on_latest })}</div>
    <div class="table-wrap"><table><thead><tr>
      <th>${t('th_version')}</th><th>${t('th_free')}</th><th>${t('th_premium')}</th><th>${t('th_total')}</th>
    </tr></thead><tbody>${rows}</tbody></table></div>`;
}

// -------------------------------------------------------------- Health ----

function renderHealth(h) {
  if (!h) return;
  const cards = [
    [t('health_exp_7d'), h.licenses_expiring_7d, ''],
    [t('health_exp_30d'), h.licenses_expiring_30d, ''],
    [t('health_clone_blocked'), h.clone_blocked_now, ''],
    [t('health_token_suspicious'), h.token_suspicious_now, ''],
    [t('health_verify_rate'), h.verify_success_rate_pct_window + '%', t('health_verify_sub', { n: fmtNum(h.verify_attempts_window) })],
  ];
  $('healthCards').innerHTML = cards.map(([label, value, sub]) => `
    <div class="card">
      <div class="label">${label}</div>
      <div class="value">${typeof value === 'number' ? fmtNum(value) : value}</div>
      ${sub ? `<div class="sub">${sub}</div>` : ''}
    </div>
  `).join('');
}

// ------------------------------------------------------- Suspicious IPs ---

function renderSuspiciousIps(s) {
  if (!s) return;
  const box = $('suspiciousIps');
  const volRows = (s.top_by_request_volume_24h || []).map((r) => `<tr><td>${escapeHtml(r.ip)}</td><td>${fmtNum(r.requests_24h)}</td></tr>`).join('');
  const failRows = (s.top_by_failed_attempts_window || []).map((r) => `<tr><td>${escapeHtml(r.ip)}</td><td>${fmtNum(r.failed_attempts)}</td></tr>`).join('');
  box.innerHTML = `
    <h3 class="small muted">${t('susp_volume_title')}</h3>
    ${volRows ? `<div class="table-wrap"><table><thead><tr><th>${t('th_ip')}</th><th>${t('th_request_count')}</th></tr></thead><tbody>${volRows}</tbody></table></div>` : `<div class="empty-state">${t('nothing_unusual')}</div>`}
    <h3 class="small muted" style="margin-top:14px;">${t('susp_fail_title')}</h3>
    ${failRows ? `<div class="table-wrap"><table><thead><tr><th>${t('th_ip')}</th><th>${t('th_failed_count')}</th></tr></thead><tbody>${failRows}</tbody></table></div>` : `<div class="empty-state">${t('nothing_unusual')}</div>`}
  `;
}

// --------------------------------------------------------- Search / ban ---

$('searchBtn').addEventListener('click', runSearch);
$('searchInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') runSearch(); });

async function runSearch() {
  const q = $('searchInput').value.trim();
  const box = $('searchResults');
  if (!q) { box.innerHTML = ''; return; }
  box.innerHTML = `<div class="empty-state">${t('searching')}</div>`;
  try {
    const data = await api(`admin_search.php?q=${encodeURIComponent(q)}`);
    renderSearchResults(data);
  } catch (e) {
    box.innerHTML = `<div class="empty-state">${t('error_prefix')}${e.message}</div>`;
  }
}

function renderSearchResults(data) {
  const box = $('searchResults');
  const rowsHtml = [];

  if (data.licenses && data.licenses.length) {
    rowsHtml.push(`<h3 class="small muted">${t('premium_licenses_title')}</h3>`);
    rowsHtml.push('<div class="table-wrap"><table><thead><tr>' +
      `<th>${t('th_email')}</th><th>${t('th_product')}</th><th>${t('th_os')}</th><th>${t('th_status')}</th><th>${t('th_last_seen')}</th><th>${t('th_ban')}</th><th></th>` +
      '</tr></thead><tbody>');
    for (const r of data.licenses) {
      rowsHtml.push(`<tr>
        <td>${escapeHtml(r.user_email)}</td>
        <td>${escapeHtml(r.product_name)}</td>
        <td>${escapeHtml(r.device_type)}</td>
        <td>${escapeHtml(r.status)}</td>
        <td>${escapeHtml(r.last_seen_at || '-')}</td>
        <td>${r.banned ? `<span class="badge banned">${t('badge_banned')}</span>` : `<span class="badge ok">${t('badge_free')}</span>`}</td>
        <td><button class="btn small ${r.banned ? '' : 'danger'}" data-ban-license="${r.id}" data-action="${r.banned ? 'unban' : 'ban'}">${r.banned ? t('action_unban') : t('action_ban')}</button></td>
      </tr>`);
    }
    rowsHtml.push('</tbody></table></div>');
  }

  if (data.free_devices && data.free_devices.length) {
    rowsHtml.push(`<h3 class="small muted">${t('free_installs_title')}</h3>`);
    rowsHtml.push('<div class="table-wrap"><table><thead><tr>' +
      `<th>${t('th_machine_id')}</th><th>${t('th_os')}</th><th>${t('th_first_seen')}</th><th>${t('th_last_seen')}</th><th>${t('th_ban')}</th><th></th>` +
      '</tr></thead><tbody>');
    for (const r of data.free_devices) {
      rowsHtml.push(`<tr>
        <td>${escapeHtml((r.machine_id || '').slice(0, 16))}…</td>
        <td>${escapeHtml(r.platform_profile || '-')}</td>
        <td>${escapeHtml(r.first_seen_at || '-')}</td>
        <td>${escapeHtml(r.last_seen_at || '-')}</td>
        <td>${r.banned ? `<span class="badge banned">${t('badge_banned')}</span>` : `<span class="badge ok">${t('badge_free')}</span>`}</td>
        <td><button class="btn small ${r.banned ? '' : 'danger'}" data-ban-free="${escapeHtml(r.machine_id || '')}" data-device-hash="${escapeHtml(r.device_public_key_hash || '')}" data-action="${r.banned ? 'unban' : 'ban'}">${r.banned ? t('action_unban') : t('action_ban')}</button></td>
      </tr>`);
    }
    rowsHtml.push('</tbody></table></div>');
  }

  if (!rowsHtml.length) {
    box.innerHTML = `<div class="empty-state">${t('nothing_found')}</div>`;
    return;
  }
  box.innerHTML = rowsHtml.join('');

  box.querySelectorAll('[data-ban-license]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const licenseId = btn.getAttribute('data-ban-license');
      const action = btn.getAttribute('data-action');
      let reason = null;
      if (action === 'ban') reason = prompt(t('ban_reason_prompt')) || '';
      try {
        await api('admin_ban.php', { method: 'POST', body: JSON.stringify({ action, scope: 'license', license_id: Number(licenseId), reason }) });
        runSearch();
        loadBannedList();
      } catch (e) { alert(t('error_prefix') + e.message); }
    });
  });

  box.querySelectorAll('[data-ban-free]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const machineId = btn.getAttribute('data-ban-free');
      const deviceHash = btn.getAttribute('data-device-hash');
      const action = btn.getAttribute('data-action');
      let reason = null;
      if (action === 'ban') reason = prompt(t('ban_reason_prompt')) || '';
      try {
        await api('admin_ban.php', { method: 'POST', body: JSON.stringify({ action, scope: 'free_device', machine_id: machineId, device_key_hash: deviceHash, reason }) });
        runSearch();
        loadBannedList();
      } catch (e) { alert(t('error_prefix') + e.message); }
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
  box.innerHTML = `<div class="empty-state">${t('loading')}</div>`;
  try {
    const data = await api('admin_search.php?scope=banned');
    if (!data.banned || !data.banned.length) {
      box.innerHTML = `<div class="empty-state">${t('nobody_banned')}</div>`;
      return;
    }
    const rows = data.banned.map((b) => `<tr>
      <td>${escapeHtml(b.scope)}</td>
      <td>${escapeHtml(b.user_email || '-')}</td>
      <td>${escapeHtml((b.machine_id || '').slice(0, 16))}${b.machine_id ? '…' : '-'}</td>
      <td>${escapeHtml(b.reason || '-')}</td>
      <td>${escapeHtml(b.banned_at)}</td>
      <td><button class="btn small" data-unban="${b.id}" data-scope="${escapeHtml(b.scope)}" data-license="${b.license_id || ''}" data-machine="${escapeHtml(b.machine_id || '')}" data-device="${escapeHtml(b.device_public_key_hash || '')}">${t('action_unban')}</button></td>
    </tr>`).join('');
    box.innerHTML = `<div class="table-wrap"><table><thead><tr>
      <th>${t('th_type')}</th><th>${t('th_email')}</th><th>${t('th_machine_id')}</th><th>${t('th_reason')}</th><th>${t('th_ban_date')}</th><th></th>
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
        } catch (e) { alert(t('error_prefix') + e.message); }
      });
    });
  } catch (e) {
    box.innerHTML = `<div class="empty-state">${t('error_prefix')}${e.message}</div>`;
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
  box.innerHTML = `<div class="empty-state">${t('searching')}</div>`;
  try {
    const params = new URLSearchParams({ page: String(page), page_size: '50' });
    if (q) params.set('q', q);
    if (reason) params.set('reason_code', reason);
    if (kind) params.set('install_kind', kind);
    const data = await api('admin_minus2.php?' + params.toString());
    renderMinus2(data);
  } catch (e) {
    box.innerHTML = `<div class="empty-state">${t('error_prefix')}${e.message}</div>`;
  }
}

function renderMinus2(data) {
  const box = $('minus2Results');
  if (!data.rows.length) {
    box.innerHTML = `<div class="empty-state">${t('nothing_found')}</div>`;
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
    <th>${t('th_time')}</th><th>${t('th_type')}</th><th>${t('th_cause')}</th><th>${t('th_email')}</th><th>${t('th_machine_id')}</th><th>${t('th_os')}</th><th>${t('th_details')}</th>
  </tr></thead><tbody>${rows}</tbody></table></div>`;

  const totalPages = Math.max(1, Math.ceil(data.total / data.page_size));
  $('minus2Pager').innerHTML = `
    <button class="btn small" id="minus2Prev" ${data.page <= 1 ? 'disabled' : ''}>${t('prev')}</button>
    <span>${t('page_of', { page: data.page, total: totalPages, rows: fmtNum(data.total) })}</span>
    <button class="btn small" id="minus2Next" ${data.page >= totalPages ? 'disabled' : ''}>${t('next')}</button>
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
