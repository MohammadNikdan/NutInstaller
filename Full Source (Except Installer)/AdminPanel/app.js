'use strict';

// ------------------------------------------------------------------- i18n ---

const DICT = {
  fa: {
    app_title: 'پنل مدیریت نوتریکولا',
    login_fingerprint_sub: 'برای ادامه اثر انگشتت رو لمس کن.',
    use_password_instead: 'ورود با رمز عبور',
    login_password_placeholder: 'رمز عبور',
    captcha_placeholder: 'کد امنیتی تصویر بالا',
    login_submit: 'ورود',
    login_failed: 'ورود ناموفق بود.',
    login_err_rate_limited: 'تلاش بیش از حد. کمی بعد دوباره امتحان کن.',
    login_err_bad_captcha: 'کد امنیتی اشتباه است.',
    login_err_wrong_password: 'رمز عبور اشتباه است.',
    login_err_internal: 'خطای داخلی سرور.',
    passkey_or: 'یا',
    passkey_login_btn: 'ورود با اثر انگشت',
    passkey_none_registered: 'هنوز دستگاهی برای ورود سریع ثبت نشده. اول با رمز وارد شو، بعد از پایین داشبورد یکی اضافه کن.',
    passkey_failed: 'ورود با اثر انگشت ناموفق بود یا لغو شد.',
    passkey_section_title: 'ورود سریع با اثر انگشت',
    passkey_section_desc: 'دستگاه‌هایی که اجازه دارن بدون رمز، فقط با اثرانگشت وارد این پنل بشن.',
    passkey_add_btn: 'افزودن این دستگاه',
    passkey_label_prompt: 'یه اسم برای این دستگاه بذار (مثلاً «گوشی من»):',
    passkey_label_default: 'دستگاه من',
    passkey_empty: 'هنوز دستگاهی ثبت نشده.',
    th_passkey_created: 'تاریخ افزودن',
    th_passkey_last_used: 'آخرین استفاده',
    action_delete: 'حذف',

    window_label: 'بازه فعال بودن:',
    window_today: 'امروز',
    window_1d: '۲۴ ساعت',
    window_7d: '۷ روز',
    window_30d: '۳۰ روز',
    window_90d: '۹۰ روز',
    window_365d: 'یک سال اخیر',
    window_all: 'کل تاریخچه',
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
    os_windows: 'ویندوز',
    os_vm: 'سرور مجازی',
    os_mac: 'مک',
    os_linux: 'لینوکس',
    os_unknown: 'ناشناخته',

    load_title: 'وضعیت و شلوغی سرور',
    conversion_title: 'نرخ تبدیل رایگان به پریمیوم',
    build_title: 'توزیع نسخه‌های نصب‌شده',
    health_title: 'سلامت و وضعیت کلی',
    suspicious_title: 'IPهای مشکوک',

    search_title: 'جستجوی کاربر / بن کردن',
    search_placeholder: 'ایمیل، machine_id یا device_key_hash یا UUID لایسنس',
    search_btn: 'جستجو',

    banned_title: 'لیست بن‌شده‌ها',
    refresh_list: 'بروزرسانی لیست',

    minus2_title: 'گزارش خطاهای بحرانی اجرا',
    minus2_placeholder: 'ایمیل یا machine_id',
    minus2_reason_all: 'همه علت‌ها',
    minus2_reason_artifact_mismatch: 'دستکاری یا خرابی فایل‌های برنامه',
    minus2_reason_transport_exhausted: 'عدم موفقیت در ارتباط با سرور لایسنس',
    minus2_reason_machineid_failed: 'خطا در شناسایی سخت‌افزار دستگاه',
    minus2_kind_all: 'رایگان و پریمیوم',
    minus2_kind_free: 'فقط رایگان',
    minus2_kind_premium: 'فقط پریمیوم',
    minus2_reason_artifact_check_failed: 'فایل برنامه روی دستگاه ناقص یا دستکاری شده (تشخیص محلی)',
    minus2_reason_license_file_invalid: 'فایل لایسنس روی دستگاه خراب یا دستکاری شده',
    minus2_reason_free_checkin_failed: 'نسخهٔ رایگان: پاسخ معتبر از سرور نیامد',
    minus2_reason_server_rejected: 'رد شدن توسط سرور (امضای نامعتبر، چالش و ...)',

    rejected_title: 'دستگاه‌های ردشده (بن‌شده، نسخهٔ قدیمی، دستکاری‌شده)',
    rejected_hint: 'این دستگاه‌ها هنگام بررسی رایگان رد شده‌اند و در آمار کاربران رایگان فعال حساب نمی‌شوند.',
    rejected_placeholder: 'machine_id یا device_key_hash',
    rejected_reason_all: 'همه علت‌ها',
    rejected_reason_banned: 'بن‌شده',
    rejected_reason_update_required: 'نسخهٔ قدیمی (نیاز به به‌روزرسانی)',
    rejected_reason_artifact_mismatch: 'دستکاری یا خرابی فایل‌ها',
    rejected_summary: 'در بازهٔ ۳۰ روز اخیر: {banned} بن‌شده، {update_required} نسخهٔ قدیمی، {artifact_mismatch} دستکاری‌شده',
    th_last_reason: 'آخرین علت',
    th_counts: 'تعداد دفعات',
    th_build: 'نسخه (build)',
    rejected_installs_title: 'دستگاه‌های ردشده',
    counts_banned: 'بن',
    counts_outdated: 'قدیمی',
    counts_tampered: 'دستکاری',

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
    pct_of_active: '<span class="pct-sign-sub">٪</span>{pct} از کل فعال',
    pct_of_total: '<span class="pct-sign-sub">٪</span>{pct} از کل',

    today_title: 'کاربران جدید و فعالیت امروز',
    card_free_brand_new: 'کاربران کاملاً جدید رایگان (امروز)',
    card_free_returning_30d: 'بازگشت رایگان بعد از ۳۰+ روز (امروز)',
    card_premium_first_time: 'فعال‌سازی اولین لایسنس (امروز)',
    card_premium_renewal: 'تمدید/فعال‌سازی مجدد لایسنس (امروز)',
    card_transfers_today: 'ترنسفرهای انجام‌شده (امروز)',
    needs_db_update: 'نیاز به بروزرسانی دیتابیس',

    label_free: 'رایگان',
    label_premium: 'پریمیوم',
    label_active_users: 'کاربران فعال',
    axis_user_count: 'تعداد کاربر',
    label_requests_per_min: 'درخواست در دقیقه',
    label_avg_response_ms: 'میانگین زمان پاسخ (ms)',

    verdict_normal: 'وضعیت سرور عادیه، مثل همیشه.',
    verdict_elevated: 'سرور این مدت یه‌کم شلوغ‌تر از حد معمولشه.',
    verdict_critical: 'وضعیت سرور بحرانیه؛ خیلی شلوغه و پاسخ‌دهی به‌شدت کند شده.',
    verdict_insufficient_data: 'هنوز داده کافی برای تحلیل وضعیت سرور جمع نشده.',
    verdict_table_missing: 'جدول ثبت زمان پاسخ (nutricula_request_timing) هنوز روی دیتابیس ساخته نشده. تا ساختنش، فقط حجم درخواست‌های یک ساعت اخیر نمایش داده میشه، نه سرعت پاسخ.',
    verdict_recent_avg: 'میانگین ۱۵ دقیقه اخیر: {ms} میلی‌ثانیه',
    verdict_baseline_avg: 'میانگین عادی (۲۴ساعت اخیر): {ms} میلی‌ثانیه',
    verdict_latency_ratio: 'نسبت کندی: {ratio}×',

    comparison_period: 'بازه',
    comparison_requests: 'تعداد درخواست',
    comparison_avg_ms: 'میانگین زمان پاسخ',
    comparison_last_24h: '۲۴ ساعت اخیر',
    comparison_last_7d: '۷ روز اخیر',
    comparison_last_30d: '۳۰ روز اخیر',
    comparison_note: 'هر بازه با بازه‌ی هم‌طول قبل از خودش مقایسه شده (مثلاً ۲۴ ساعت اخیر با ۲۴ ساعت قبل از اون) - ربطی به ساعت یا نیمه‌شب نداره.',

    unit_ms: 'ms',
    unit_mb: 'MB',
    system_load_1m_label: 'بار سیستم (۱ دقیقه)',
    system_load_5m_label: 'بار سیستم (۵ دقیقه)',
    system_load_15m_label: 'بار سیستم (۱۵ دقیقه)',
    system_cpu_cores_label: 'تعداد هسته CPU',
    system_mem_label: 'مصرف RAM',
    system_unavailable: 'اطلاعات CPU و RAM روی این هاست در دسترس نیست (محدودیت هاست اشتراکی).',

    conv_in_window: 'تبدیل‌شده در بازه انتخابی',
    conv_all_time: 'تبدیل‌شده (کل تاریخچه)',
    pct_of_free: '<span class="pct-sign-sub">٪</span>{pct} از کل رایگان‌ها',
    conv_avg_days: 'میانگین روز تا تبدیل',

    build_empty: 'هنوز داده‌ای برای نسخه‌ی نصب‌شده ثبت نشده.',
    build_latest_label: 'آخرین نسخه‌ی منتشرشده:',
    build_pct_suffix: '<span class="pct-sign-sub">٪</span>{pct} از نصب‌های فعال با نسخه‌ی مشخص روی آخرین نسخه‌اند.',
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
    login_fingerprint_sub: 'Touch your fingerprint sensor to continue.',
    use_password_instead: 'Sign in with password',
    login_password_placeholder: 'Password',
    captcha_placeholder: 'Security code from the image above',
    login_submit: 'Sign in',
    login_failed: 'Sign-in failed.',
    login_err_rate_limited: 'Too many attempts. Try again later.',
    login_err_bad_captcha: 'Security code is incorrect.',
    login_err_wrong_password: 'Incorrect password.',
    login_err_internal: 'Internal error.',
    passkey_or: 'or',
    passkey_login_btn: 'Sign in with fingerprint',
    passkey_none_registered: 'No passkey registered yet. Sign in with your password first, then add one near the bottom of the dashboard.',
    passkey_failed: 'Fingerprint sign-in failed or was cancelled.',
    passkey_section_title: 'Fingerprint quick sign-in',
    passkey_section_desc: 'Devices allowed to sign in to this panel with just a fingerprint, no password.',
    passkey_add_btn: 'Add this device',
    passkey_label_prompt: 'Name this device (e.g. "My phone"):',
    passkey_label_default: 'My device',
    passkey_empty: 'No devices registered yet.',
    th_passkey_created: 'Added',
    th_passkey_last_used: 'Last used',
    action_delete: 'Remove',

    window_label: 'Active window:',
    window_today: 'Today',
    window_1d: '24 hours',
    window_7d: '7 days',
    window_30d: '30 days',
    window_90d: '90 days',
    window_365d: 'Last year',
    window_all: 'All time',
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
    os_windows: 'Windows',
    os_vm: 'VPS',
    os_mac: 'Mac',
    os_linux: 'Linux',
    os_unknown: 'Unknown',

    load_title: 'Server health & load',
    conversion_title: 'Free-to-premium conversion rate',
    build_title: 'Installed Version Breakdown',
    health_title: 'Health & overall status',
    suspicious_title: 'Suspicious IPs',

    search_title: 'Search users / ban',
    search_placeholder: 'Email, machine_id, device_key_hash or license UUID',
    search_btn: 'Search',

    banned_title: 'Banned list',
    refresh_list: 'Refresh list',

    minus2_title: 'Critical Failure Reports',
    minus2_placeholder: 'Email or machine_id',
    minus2_reason_all: 'All reasons',
    minus2_reason_artifact_mismatch: 'App files tampered or corrupted',
    minus2_reason_transport_exhausted: "Couldn't reach the license server",
    minus2_reason_machineid_failed: 'Failed to identify device hardware',
    minus2_kind_all: 'Free & premium',
    minus2_kind_free: 'Free only',
    minus2_kind_premium: 'Premium only',
    minus2_reason_artifact_check_failed: 'App file missing or modified on the device (local check)',
    minus2_reason_license_file_invalid: 'License file on the device is corrupted or modified',
    minus2_reason_free_checkin_failed: 'Free install: no valid answer from the server',
    minus2_reason_server_rejected: 'Rejected by the server (invalid signature, challenge, …)',

    rejected_title: 'Rejected devices (banned, outdated, tampered)',
    rejected_hint: 'These devices were refused at the free check-in and are not counted as active free users.',
    rejected_placeholder: 'machine_id or device_key_hash',
    rejected_reason_all: 'All reasons',
    rejected_reason_banned: 'Banned',
    rejected_reason_update_required: 'Outdated build (update required)',
    rejected_reason_artifact_mismatch: 'Files tampered or corrupted',
    rejected_summary: 'Last 30 days: {banned} banned, {update_required} outdated, {artifact_mismatch} tampered',
    th_last_reason: 'Last reason',
    th_counts: 'Times seen',
    th_build: 'Build',
    rejected_installs_title: 'Rejected devices',
    counts_banned: 'banned',
    counts_outdated: 'outdated',
    counts_tampered: 'tampered',

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
    pct_of_active: '{pct}<span class="pct-sign-sub">%</span> of active total',
    pct_of_total: '{pct}<span class="pct-sign-sub">%</span> of total',

    today_title: "Today's new users & activity",
    card_free_brand_new: 'Brand-new free users (today)',
    card_free_returning_30d: 'Free users returning after 30+ days (today)',
    card_premium_first_time: 'First-time license activations (today)',
    card_premium_renewal: 'License renewals/reactivations (today)',
    card_transfers_today: 'Transfers completed (today)',
    needs_db_update: 'Needs a database update',

    label_free: 'Free',
    label_premium: 'Premium',
    label_active_users: 'Active users',
    axis_user_count: 'Number of users',
    label_requests_per_min: 'Requests/min',
    label_avg_response_ms: 'Avg response time (ms)',

    verdict_normal: 'Server status is normal, as usual.',
    verdict_elevated: 'The server is somewhat busier than usual right now.',
    verdict_critical: 'Server status is critical - very busy, and response times have slowed sharply.',
    verdict_insufficient_data: 'Not enough data collected yet to analyze server status.',
    verdict_table_missing: 'The response-time table (nutricula_request_timing) hasn\'t been created in the database yet. Until it is, only the last hour\'s request volume is shown here, not response speed.',
    verdict_recent_avg: 'Last 15 min average: {ms} ms',
    verdict_baseline_avg: 'Normal baseline (last 24h): {ms} ms',
    verdict_latency_ratio: 'Slowdown ratio: {ratio}x',

    comparison_period: 'Period',
    comparison_requests: 'Requests',
    comparison_avg_ms: 'Avg response time',
    comparison_last_24h: 'Last 24 hours',
    comparison_last_7d: 'Last 7 days',
    comparison_last_30d: 'Last 30 days',
    comparison_note: 'Each period is compared against the equal-length period right before it (e.g. the last 24h vs the 24h before that) - independent of clock time or midnight.',

    unit_ms: 'ms',
    unit_mb: 'MB',
    system_load_1m_label: 'System load (1 min)',
    system_load_5m_label: 'System load (5 min)',
    system_load_15m_label: 'System load (15 min)',
    system_cpu_cores_label: 'CPU cores',
    system_mem_label: 'RAM usage',
    system_unavailable: 'CPU/RAM data isn\'t available on this host (a shared-hosting restriction).',

    conv_in_window: 'Converted in selected window',
    conv_all_time: 'Converted (all-time)',
    pct_of_free: '{pct}<span class="pct-sign-sub">%</span> of all free users',
    conv_avg_days: 'Avg. days to convert',

    build_empty: 'No installed-version data recorded yet.',
    build_latest_label: 'Latest published version:',
    build_pct_suffix: '{pct}<span class="pct-sign-sub">%</span> of active installs with a known version are on the latest.',
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

// The timezone is never user-editable - it's read straight from the
// device (phone, laptop, whatever browser this panel is open in) via the
// standard Intl API, which every modern Android/iOS/Windows/macOS/Linux
// browser supports. Every "today" boundary in the dashboard is anchored to
// local midnight IN THIS ZONE. Falls back to UTC only in the (practically
// never happening) case the API itself is unavailable.
function detectInitialTz() {
  try {
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    if (tz) return tz;
  } catch (e) { /* ignore */ }
  return 'UTC';
}

// IANA zone names are "Area/City" (occasionally "Area/Region/City") - the
// panel only ever displays the city part, e.g. "Asia/Tehran" -> "Tehran",
// "America/Argentina/Buenos_Aires" -> "Buenos Aires".
function tzCityName(tz) {
  const parts = String(tz).split('/');
  return parts[parts.length - 1].replace(/_/g, ' ');
}

const state = {
  csrf: null,
  stats: null,
  charts: {},
  minus2Page: 1,
  searchPage: 1,
  bannedPage: 1,
  lang: detectInitialLang(),
  tz: detectInitialTz(),
  lastUpdatedAt: null,
  lastUpdateError: null,
};

const $ = (id) => document.getElementById(id);

function t(key, vars) {
  const dict = DICT[state.lang] || DICT.fa;
  let str = dict[key] ?? DICT.fa[key] ?? key;
  if (vars) {
    for (const k of Object.keys(vars)) {
      const v = vars[k];
      str = str.replace(`{${k}}`, typeof v === 'number' ? fmtNum(v) : v);
    }
  }
  return str;
}

function fmtNum(n) {
  const locale = state.lang === 'fa' ? 'fa-IR' : 'en-US';
  return new Intl.NumberFormat(locale).format(n ?? 0);
}

// The Persian percent sign is ٪, not the Latin %, AND in Persian it comes
// BEFORE the number ("٪45") while English keeps the number first ("45%").
// Also returns the sign wrapped in its own element so CSS can render it
// much smaller than the number - every caller inserts this via innerHTML,
// never textContent, which is why the markup is safe to embed here.
function fmtPct(n) {
  const num = fmtNum(n);
  const sign = `<span class="pct-sign">${state.lang === 'fa' ? '٪' : '%'}</span>`;
  return state.lang === 'fa' ? `${sign}${num}` : `${num}${sign}`;
}

// For raw date/time strings straight from the server (e.g. "2026-10-04
// 12:30:00") - just swaps the digits, no calendar conversion, so it stays
// recognizable/sortable while still matching the rest of the Persian UI.
// Kept for pure clock-time strings (no calendar date attached, e.g. the
// server-health chart's "H:i" minute labels) where there is no calendar to
// convert - see fmtDateTime() below for anything with an actual date.
const FA_DIGITS = ['۰', '۱', '۲', '۳', '۴', '۵', '۶', '۷', '۸', '۹'];
function localizeDigits(str) {
  if (state.lang !== 'fa' || str == null) return str;
  return String(str).replace(/[0-9]/g, (d) => FA_DIGITS[d]);
}

// Every date shown in the panel: Gregorian with Latin digits in English,
// Jalali/Shamsi with Persian digits in Persian - never just a digit swap on
// the Gregorian calendar. Accepts the raw "YYYY-MM-DD[ HH:MM[:SS]]" strings
// the backend sends (MySQL datetimes / gmdate output). The Y-M-D triple is
// turned into a UTC-midnight Date purely so Intl has a calendar date to
// convert - that instant is never shown, so it can't shift the result
// across a timezone boundary; the clock-time part (if present) is passed
// through untouched except for digit localization, since a clock reading
// doesn't change between calendars.
function fmtDateTime(raw) {
  if (raw === null || raw === undefined || raw === '') return '-';
  const s = String(raw).trim();
  if (s === '-') return s;
  const m = s.match(/^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2})(?::(\d{2}))?)?/);
  if (!m) return localizeDigits(s);
  const [, y, mo, da, hh, mi] = m;
  const utcDate = new Date(Date.UTC(Number(y), Number(mo) - 1, Number(da)));
  const datePart = state.lang === 'fa'
    ? new Intl.DateTimeFormat('fa-IR-u-ca-persian', { year: 'numeric', month: '2-digit', day: '2-digit', timeZone: 'UTC' }).format(utcDate)
    : new Intl.DateTimeFormat('en-US', { year: 'numeric', month: '2-digit', day: '2-digit', timeZone: 'UTC' }).format(utcDate);
  if (hh === undefined) return datePart;
  const timePart = localizeDigits(`${hh}:${mi}`);
  return `${datePart} ${timePart}`;
}

// Same calendar conversion as fmtDateTime(), but for a growth-chart bucket
// that only has a representative Date object (no time-of-day) and a
// granularity. The year is always included ("Oct 4, 2026" / "۱۲ مهر ۱۴۰۵") -
// the "all time"/"last year" windows can span a year boundary, where a
// bare "Oct 4" would be ambiguous about which year it is.
function fmtChartDate(date, granularity) {
  const locale = state.lang === 'fa' ? 'fa-IR-u-ca-persian' : 'en-US';
  const options = granularity === 'month'
    ? { year: 'numeric', month: 'short', timeZone: 'UTC' }
    : { year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC' };
  return new Intl.DateTimeFormat(locale, options).format(date);
}

// Canvas text (chart axis ticks, legend labels, tooltips) doesn't inherit
// CSS font-family the way HTML does, so Chart.js's own global default has
// to be pointed at the right font explicitly - otherwise it silently falls
// back to its built-in default font regardless of language. This is called
// once at startup and again on every language switch.
function applyChartFontDefaults() {
  if (typeof Chart === 'undefined') return;
  Chart.defaults.font.family = state.lang === 'fa'
    ? "'Estedad', 'Segoe UI', Tahoma, sans-serif"
    : "'Outfit', 'Segoe UI', sans-serif";
}
applyChartFontDefaults();

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
  applyChartFontDefaults();
  renderLastUpdated();
  // Re-render anything already on screen so it picks up the new language.
  if (state.stats) {
    safeRender(() => renderToday(state.stats.today));
    safeRender(() => renderSummary(state.stats));
    safeRender(() => renderGrowthChart());
    safeRender(() => renderOsChart());
    safeRender(() => renderServerHealth(state.stats.server_health));
    safeRender(() => renderConversion(state.stats.conversion));
    safeRender(() => renderBuildAdoption(state.stats.build_adoption));
    safeRender(() => renderHealth(state.stats.health));
    safeRender(() => renderSuspiciousIps(state.stats.suspicious_ips));
  }
  if ($('searchInput') && $('searchInput').value.trim()) runSearch(state.searchPage || 1);
  loadBannedList();
  searchMinus2(state.minus2Page || 1);
  searchRejected(state.rejectedPage || 1);
  if (!$('dashboard').hidden) loadPasskeys();
}

document.querySelectorAll('[data-lang-btn]').forEach((btn) => {
  btn.addEventListener('click', () => setLang(btn.getAttribute('data-lang-btn')));
});

applyStaticTranslations();

// --------------------------------------------------------- Password show ---

// A single <svg> whose inner markup we swap, rather than two sibling <svg>
// elements toggled with the `hidden` attribute - some mobile WebKit/Chromium
// builds don't apply the UA default `[hidden]{display:none}` rule reliably
// to inline SVG (a long-standing cross-browser inconsistency), which showed
// up as both eye icons rendering side by side on phones.
const EYE_OPEN_SVG = '<path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z"/><circle cx="12" cy="12" r="3"/>';
const EYE_OFF_SVG = '<path d="M17.94 17.94A10.94 10.94 0 0 1 12 19c-7 0-11-7-11-7a21.3 21.3 0 0 1 5.17-5.94M9.9 4.24A10.4 10.4 0 0 1 12 4c7 0 11 7 11 7a21.3 21.3 0 0 1-2.61 3.57M14.12 14.12a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>';

const pwdInput = $('loginPassword');
const toggleBtn = $('togglePasswordBtn');
const eyeSvg = $('eyeSvg');
if (toggleBtn && pwdInput && eyeSvg) {
  toggleBtn.addEventListener('click', () => {
    const show = pwdInput.type === 'password';
    pwdInput.type = show ? 'text' : 'password';
    eyeSvg.innerHTML = show ? EYE_OFF_SVG : EYE_OPEN_SVG;
  });
}

// ----------------------------------------------------- Passkey (WebAuthn) ---

function b64urlToBuf(b64url) {
  const pad = '='.repeat((4 - (b64url.length % 4)) % 4);
  const base64 = (b64url + pad).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  const buf = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
  return buf.buffer;
}
function bufToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let str = '';
  for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// --------------------------------------------------- Login view switching ---
//
// Two views share the login screen: the password form (#loginForm, the
// default everywhere) and a fingerprint-first view (#fingerprintCard). A
// touch device that already has at least one fingerprint registered opens
// straight into the fingerprint view instead, since typing a password on a
// phone is the whole annoyance this feature exists to remove. Desktop
// always opens on the password form - its own small "sign in with
// fingerprint" button below still works exactly as before.
//
// Whether a passkey exists can only really be known by asking the server,
// which is also a rate-limited endpoint shared with login attempts itself -
// so rather than asking on every single page load, the last known answer is
// cached in localStorage (refreshed on every successful login and on every
// add/remove in the dashboard's passkey list) and used to pick the view
// instantly, before any network round trip.
function hasRememberedPasskey() {
  try { return localStorage.getItem('nutricula_admin_has_passkey') === '1'; } catch (e) { return false; }
}
function rememberPasskeyAvailability(has) {
  try { localStorage.setItem('nutricula_admin_has_passkey', has ? '1' : '0'); } catch (e) { /* ignore */ }
}
function isMobileDevice() {
  return !!(window.matchMedia && window.matchMedia('(pointer: coarse)').matches);
}
function showFingerprintLoginView() {
  $('loginForm').hidden = true;
  $('fingerprintCard').hidden = false;
}
// loadImage defaults to true for every caller EXCEPT the very first,
// synchronous call below - see the comment on resetLoginView() for why.
function showPasswordLoginView(loadImage = true) {
  $('fingerprintCard').hidden = true;
  $('loginForm').hidden = false;
  if (loadImage) loadCaptcha();
}

// CAPTCHA is only ever needed on the password path - fingerprint login never
// touches this. Cache-busted query param on every (re)load since the server
// generates a brand-new code/image on every single request to admin_captcha.php.
function loadCaptcha() {
  if (!$('captchaImg')) return;
  $('captchaImg').src = 'admin_captcha.php?r=' + Date.now() + Math.random().toString(36).slice(2);
  if ($('captchaInput')) $('captchaInput').value = '';
}
function resetLoginView(loadImage = true) {
  if (isMobileDevice() && hasRememberedPasskey()) {
    showFingerprintLoginView();
  } else {
    showPasswordLoginView(loadImage);
  }
}
// decide synchronously, before the platform check below, so there's no
// visible flash of the wrong view - but WITHOUT fetching a captcha image
// yet (loadImage: false). showLogin() (below) does that exactly once, after
// checkSession() confirms this is actually where the page is staying.
// Firing a second, independent admin_captcha.php request here used to race
// the one from showLogin(): both write their own code into the SAME PHP
// session, and whichever request's write happens to land last on the
// server isn't necessarily the one whose image the browser ends up
// displaying - so the code shown on screen and the code the server
// expected could silently be two different ones, on every single first
// page load, which looked exactly like "the first login attempt always
// says the captcha is wrong, the second always works" (the second attempt
// uses a freshly reloaded, un-raced captcha).
resetLoginView(false);

if ($('switchToPasswordBtn')) {
  $('switchToPasswordBtn').addEventListener('click', showPasswordLoginView);
}
if ($('captchaRefreshBtn')) {
  $('captchaRefreshBtn').addEventListener('click', loadCaptcha);
}

// Feature-detect, then ALSO check a platform authenticator (Face ID/Touch
// ID/fingerprint, not a USB security key) is actually usable here - showing
// the button on a desktop with no biometric hardware would just be a dead
// end. Runs once at load; nothing in this panel changes it mid-session.
(async () => {
  let platformAvailable = false;
  if (window.PublicKeyCredential && navigator.credentials) {
    try { platformAvailable = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(); } catch (e) { platformAvailable = false; }
  }
  if (platformAvailable) {
    if ($('passkeyLoginBtn')) $('passkeyLoginBtn').hidden = false;
    if ($('passkeyDivider')) $('passkeyDivider').hidden = false;
    if ($('passkeyAddBtn')) $('passkeyAddBtn').hidden = false;
    // The whole point of opening straight into the fingerprint view is not
    // having to tap anything - so when that view is showing, fire the
    // sensor prompt immediately instead of waiting for a press on
    // #passkeyPrimaryBtn. Silent: if the browser refuses to prompt without
    // a prior user gesture, or the sensor fails for any other reason, this
    // fails quietly and the button stays there for a normal manual tap -
    // no alarming error for something the person never asked for yet.
    if ($('fingerprintCard') && !$('fingerprintCard').hidden) {
      attemptPasskeyLogin('fingerprintError', { silent: true });
    }
  } else {
    // This exact browser/device can't do platform biometrics at all - a
    // cached "a passkey exists" flag (e.g. left over from a different
    // device or a reinstalled browser) is useless here.
    rememberPasskeyAvailability(false);
    if ($('fingerprintCard') && !$('fingerprintCard').hidden) showPasswordLoginView();
  }
})();

async function attemptPasskeyLogin(errorBoxId, options) {
  const silent = !!(options && options.silent);
  const errorBox = $(errorBoxId);
  if (errorBox) errorBox.hidden = true;
  try {
    const opts = await api('admin_passkey_login_options.php', { method: 'POST' });
    if (!opts.available) {
      rememberPasskeyAvailability(false);
      if (silent) { showPasswordLoginView(); return; }
      if (errorBox) { errorBox.textContent = t('passkey_none_registered'); errorBox.hidden = false; }
      return;
    }
    const publicKey = {
      challenge: b64urlToBuf(opts.challenge),
      rpId: opts.rpId,
      allowCredentials: opts.allowCredentials.map((c) => Object.assign({}, c, { id: b64urlToBuf(c.id) })),
      userVerification: opts.userVerification,
      timeout: opts.timeout,
    };
    const cred = await navigator.credentials.get({ publicKey });
    const payload = {
      rawId: bufToB64url(cred.rawId),
      response: {
        clientDataJSON: bufToB64url(cred.response.clientDataJSON),
        authenticatorData: bufToB64url(cred.response.authenticatorData),
        signature: bufToB64url(cred.response.signature),
      },
    };
    const data = await api('admin_passkey_login_verify.php', { method: 'POST', body: JSON.stringify(payload) });
    state.csrf = data.csrf;
    rememberPasskeyAvailability(true);
    await confirmSessionThenShowDashboard();
  } catch (e) {
    // The user cancelling the Face ID/fingerprint prompt, or it timing
    // out, surfaces here as a thrown DOMException (commonly
    // NotAllowedError) - not a real failure worth alarming over. For a
    // silent auto-attempt, the most likely cause is simply that this
    // browser refuses to prompt without a prior tap - say nothing and
    // leave the big button there to tap normally.
    if (silent) return;
    if (errorBox) { errorBox.textContent = t('passkey_failed'); errorBox.hidden = false; }
  }
}

if ($('passkeyLoginBtn')) {
  $('passkeyLoginBtn').addEventListener('click', () => attemptPasskeyLogin('loginError'));
}
if ($('passkeyPrimaryBtn')) {
  $('passkeyPrimaryBtn').addEventListener('click', () => attemptPasskeyLogin('fingerprintError'));
}

if ($('passkeyAddBtn')) {
  $('passkeyAddBtn').addEventListener('click', async () => {
    try {
      const opts = await api('admin_passkey_register_options.php');
      const publicKey = {
        challenge: b64urlToBuf(opts.challenge),
        rp: opts.rp,
        user: { id: b64urlToBuf(opts.user.id), name: opts.user.name, displayName: opts.user.displayName },
        pubKeyCredParams: opts.pubKeyCredParams,
        authenticatorSelection: opts.authenticatorSelection,
        attestation: opts.attestation,
        timeout: opts.timeout,
        excludeCredentials: (opts.excludeCredentials || []).map((c) => Object.assign({}, c, { id: b64urlToBuf(c.id) })),
      };
      const cred = await navigator.credentials.create({ publicKey });
      const label = prompt(t('passkey_label_prompt'), t('passkey_label_default')) || t('passkey_label_default');
      const payload = {
        rawId: bufToB64url(cred.rawId),
        label,
        response: {
          clientDataJSON: bufToB64url(cred.response.clientDataJSON),
          attestationObject: bufToB64url(cred.response.attestationObject),
        },
      };
      await api('admin_passkey_register_verify.php', { method: 'POST', body: JSON.stringify(payload) });
      loadPasskeys();
    } catch (e) {
      alert(t('error_prefix') + (e && e.message ? e.message : e));
    }
  });
}

async function loadPasskeys() {
  const box = $('passkeyList');
  if (!box) return;
  box.innerHTML = `<div class="empty-state">${t('loading')}</div>`;
  try {
    const data = await api('admin_passkey_list.php');
    rememberPasskeyAvailability(!!(data.passkeys && data.passkeys.length));
    if (!data.passkeys || !data.passkeys.length) {
      box.innerHTML = `<div class="empty-state">${t('passkey_empty')}</div>`;
      return;
    }
    box.innerHTML = data.passkeys.map((p) => `
      <div class="passkey-row">
        <div class="meta">
          <span class="name">${escapeHtml(p.label)}</span>
          <span class="dates">${t('th_passkey_created')}: ${escapeHtml(fmtDateTime(p.created_at))}${p.last_used_at ? ' · ' + t('th_passkey_last_used') + ': ' + escapeHtml(fmtDateTime(p.last_used_at)) : ''}</span>
        </div>
        <button class="btn small danger" data-passkey-del="${p.id}">${t('action_delete')}</button>
      </div>
    `).join('');
    box.querySelectorAll('[data-passkey-del]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        try {
          await api('admin_passkey_delete.php', { method: 'POST', body: JSON.stringify({ id: Number(btn.getAttribute('data-passkey-del')) }) });
          loadPasskeys();
        } catch (e) { alert(t('error_prefix') + e.message); }
      });
    });
  } catch (e) {
    box.innerHTML = `<div class="empty-state">${t('error_prefix')}${e.message}</div>`;
  }
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
    let msg = (data && data.error) ? data.error : ('HTTP ' + res.status);
    if (data && data.debug) msg += ' — ' + data.debug; // temporary server-side diagnostic, see admin_stats.php
    const err = new Error(msg);
    // The server's "error" text is always English (it's also what lands in
    // the audit log) - a stable "code" field alongside it is what callers
    // use to show the person a properly localized message instead, falling
    // back to this raw English text only for codes with no translation yet.
    if (data && data.code) err.code = data.code;
    throw err;
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
  $('langSwitch').hidden = false; // floating switch is for the login screen only
  resetLoginView();
}

function showDashboard() {
  $('loginScreen').hidden = true;
  $('dashboard').hidden = false;
  $('langSwitch').hidden = true; // the topbar has its own inline copy (#langSwitchInline)
  refreshAll();
  startAutoRefresh();
  loadBannedList();
  searchMinus2(1);
  loadPasskeys();
}

// After a successful login/passkey sign-in, confirm the new session is
// actually visible before switching screens, with one short retry. On a
// few shared hosts the very first follow-up request can land a beat before
// the just-written session is readable; without this, the dashboard would
// flash open and then immediately bounce back to the password screen
// (seen only on mobile, where the follow-up requests fire fastest).
async function confirmSessionThenShowDashboard() {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const data = await api('admin_session.php');
      if (data.authenticated) {
        if (data.csrf) state.csrf = data.csrf;
        showDashboard();
        return;
      }
    } catch (e) { /* treat like not-yet-authenticated and retry below */ }
    if (attempt < 2) {
      await new Promise((resolve) => setTimeout(resolve, 350));
    }
  }
  $('loginError').textContent = t('login_failed');
  $('loginError').hidden = false;
}

$('loginForm').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  if ($('loginSubmitBtn').disabled) return; // ignore a double-tap/duplicate submit
  $('loginError').hidden = true;
  $('loginSubmitBtn').disabled = true;
  const password = $('loginPassword').value;
  const captcha = $('captchaInput') ? $('captchaInput').value : '';
  try {
    const data = await api('admin_login.php', { method: 'POST', body: JSON.stringify({ password, captcha }) });
    state.csrf = data.csrf;
    $('loginPassword').value = '';
    await confirmSessionThenShowDashboard();
  } catch (e) {
    $('loginError').textContent = loginErrorText(e);
    $('loginError').hidden = false;
    // The server consumes the captcha code on every attempt, pass or fail -
    // so whatever was shown is no longer valid either way. Get a fresh one.
    loadCaptcha();
  } finally {
    $('loginSubmitBtn').disabled = false;
  }
});

// admin_login.php's "error" text is always English (also what the audit log
// stores) - it sends a stable "code" alongside it precisely so the message
// actually shown to the person can follow whichever language the panel is
// currently in. Falls back to the raw server text for a code with no
// translation yet (or no code at all, e.g. a plain network failure).
const LOGIN_ERROR_KEYS = {
  rate_limited: 'login_err_rate_limited',
  bad_captcha: 'login_err_bad_captcha',
  wrong_password: 'login_err_wrong_password',
  internal_error: 'login_err_internal',
};
function loginErrorText(e) {
  const key = e && e.code && LOGIN_ERROR_KEYS[e.code];
  return key ? t(key) : ((e && e.message) || t('login_failed'));
}

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

// Renders "<device city> - <time>" into #lastUpdated from whatever
// happened last (a successful refresh or an error) - called both right
// after that happens and from setLang(), so a language switch alone
// updates the calendar/digits/sign without needing a fresh refresh.
function renderLastUpdated() {
  const el = $('lastUpdated');
  if (!el) return;
  if (state.lastUpdateError) {
    el.textContent = t('refresh_error_prefix') + state.lastUpdateError;
    return;
  }
  if (!state.lastUpdatedAt) return;
  const locale = state.lang === 'fa' ? 'fa-IR' : 'en-US';
  const time = state.lastUpdatedAt.toLocaleTimeString(locale);
  el.textContent = `${t('last_updated_prefix')}${tzCityName(state.tz)} - ${time}`;
}

// Runs a render function without letting one broken section (e.g. a chart
// library that failed to load) throw and abort every render call queued
// after it in the same function - that used to leave the rest of the
// dashboard (and, from setLang(), the rest of the language switch) stuck
// however far the crash got.
function safeRender(fn) {
  try { fn(); } catch (e) { console.error('[Nutricula admin] render failed:', e); }
}

// Builds the admin_stats.php query string for whatever the window selector
// is currently set to - a plain day count, 'today' (local-midnight based)
// or 'all' (no lower bound). See admin_stats.php's own doc comment for how
// each of these is interpreted.
function buildWindowQuery() {
  const sel = $('windowDays').value;
  const params = new URLSearchParams();
  params.set('growth_days', '365');
  params.set('tz', state.tz);
  if (sel === 'today' || sel === 'all') {
    params.set('range', sel);
  } else {
    params.set('days', sel);
  }
  return params.toString();
}

async function refreshAll(isRetry) {
  try {
    const data = await api(`admin_stats.php?${buildWindowQuery()}`);
    state.stats = data;
    safeRender(() => renderToday(data.today));
    safeRender(() => renderSummary(data));
    safeRender(() => renderGrowthChart());
    safeRender(() => renderOsChart());
    safeRender(() => renderServerHealth(data.server_health));
    safeRender(() => renderConversion(data.conversion));
    safeRender(() => renderBuildAdoption(data.build_adoption));
    safeRender(() => renderHealth(data.health));
    safeRender(() => renderSuspiciousIps(data.suspicious_ips));
    state.lastUpdatedAt = new Date();
    state.lastUpdateError = null;
    renderLastUpdated();
  } catch (e) {
    if (String(e.message).includes('Not authenticated') || String(e.message).includes('Session expired')) {
      // One short, silent retry before giving up - guards against the same
      // brief just-after-login session-visibility race this endpoint can
      // hit right after showDashboard() fires its first batch of requests.
      if (!isRetry) {
        await new Promise((resolve) => setTimeout(resolve, 350));
        return refreshAll(true);
      }
      showLogin();
      return;
    }
    state.lastUpdateError = e.message;
    renderLastUpdated();
  }
}

// --------------------------------------------------------- Today cards ----
// "Today" = since local midnight in the selected timezone - resets to zero
// every midnight - and always NEW-acquisition signals (brand-new free
// users, free users coming back after a long gap, first-time and renewal
// premium activations, transfers), never just "who happened to use the app
// today" (that's not a signal worth a dedicated card on its own).

function renderToday(today) {
  if (!today) return;
  const cards = [
    [t('card_free_brand_new'), today.free_brand_new, ''],
    [t('card_free_returning_30d'), today.free_returning_30d, today.free_returning_available ? '' : t('needs_db_update')],
    [t('card_premium_first_time'), today.premium_first_time, ''],
    [t('card_premium_renewal'), today.premium_renewal, ''],
    [t('card_transfers_today'), today.transfers, ''],
  ];
  $('todayCards').innerHTML = cards.map(([label, value, sub]) => `
    <div class="card">
      <div class="label" title="${label}">${label}</div>
      <div class="value">${fmtNum(value)}</div>
      ${sub ? `<div class="sub">${sub}</div>` : ''}
    </div>
  `).join('');
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
      <div class="label" title="${label}">${label}</div>
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
    if (!buckets.has(key)) buckets.set(key, { date: d, free_new: 0, premium_new: 0, free_cumulative: row.free_cumulative, premium_cumulative: row.premium_cumulative });
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
  const keys = Array.from(buckets.keys());
  const labels = keys.map((k) => fmtChartDate(buckets.get(k).date, granularity));
  const freeKey = metric === 'new' ? 'free_new' : 'free_cumulative';
  const premiumKey = metric === 'new' ? 'premium_new' : 'premium_cumulative';
  const freeData = keys.map((k) => buckets.get(k)[freeKey]);
  const premiumData = keys.map((k) => buckets.get(k)[premiumKey]);

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
    options: chartBaseOptions(t('axis_user_count')),
  });
}

$('growthGranularity').addEventListener('change', renderGrowthChart);
$('growthMetric').addEventListener('change', renderGrowthChart);

// ------------------------------------------------------------- OS chart ---

function renderOsChart() {
  if (!state.stats) return;
  const segment = $('osSegment').value;
  const rows = state.stats.by_os;
  const labels = rows.map((r) => t('os_' + r.platform));
  const data = rows.map((r) => r[segment]);

  const ctx = $('osChart').getContext('2d');
  if (state.charts.os) state.charts.os.destroy();
  state.charts.os = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{ label: t('label_active_users'), data, backgroundColor: '#0f9d73', borderRadius: 6, maxBarThickness: 42 }],
    },
    options: chartBaseOptions(t('label_active_users')),
  });
}

$('osSegment').addEventListener('change', renderOsChart);

// --------------------------------------------------------- Server health ---
// Real server-busyness signal: RESPONSE SPEED (avg ms/request), not just
// request volume - a traffic spike the server handles fine isn't "busy" in
// any way that matters, a slowdown at normal traffic is. See admin_stats.php's
// server_health block for how the verdict and the day-over-day comparison
// are computed.

function renderServerHealth(health) {
  if (!health) return;
  renderHealthChart(health.last_hour || []);
  renderHealthVerdict(health);
  if (health.available) {
    renderHealthComparison(health.comparison);
    renderHealthSystem(health.system);
  } else {
    if ($('healthComparison')) $('healthComparison').innerHTML = '';
    if ($('healthSystem')) $('healthSystem').innerHTML = '';
  }
}

function renderHealthChart(series) {
  const labels = series.map((r) => localizeDigits(r.minute));
  const requests = series.map((r) => r.requests);
  const avgMs = series.map((r) => r.avg_ms);
  const hasLatency = series.some((r) => r.avg_ms !== null && r.avg_ms !== undefined);
  const ctx = $('loadChart').getContext('2d');
  if (state.charts.load) state.charts.load.destroy();
  const datasets = [
    { type: 'bar', label: t('label_requests_per_min'), data: requests, backgroundColor: 'rgba(33,30,99,0.28)', borderRadius: 4, maxBarThickness: 24, yAxisID: 'y' },
  ];
  if (hasLatency) {
    datasets.push({ type: 'line', label: t('label_avg_response_ms'), data: avgMs, borderColor: '#d8485a', backgroundColor: 'rgba(216,72,90,0.12)', tension: 0.25, fill: false, borderWidth: 2.5, pointRadius: 0, yAxisID: 'y1', spanGaps: true });
  }
  state.charts.load = new Chart(ctx, {
    data: { labels, datasets },
    options: {
      responsive: true,
      plugins: { legend: { labels: { color: '#43534c', font: { family: getComputedStyle(document.body).fontFamily } } } },
      scales: {
        x: { ticks: { color: '#7a8780' }, grid: { color: 'rgba(23,35,30,0.07)' } },
        // Requests/min is always a whole count - force integer ticks
        // (precision: 0) so it never shows a fractional request. Avg
        // response time is a genuinely fractional measurement (rounded to
        // 0.1ms server-side), so its own axis is left to pick its own
        // decimal ticks rather than being forced either way.
        y: {
          position: 'left', beginAtZero: true,
          ticks: { color: '#7a8780', precision: 0, callback: (v) => fmtNum(v) },
          grid: { color: 'rgba(23,35,30,0.07)' },
          title: { display: true, text: t('label_requests_per_min'), color: '#43534c' },
        },
        y1: {
          position: 'right', beginAtZero: true, display: hasLatency,
          ticks: { color: '#7a8780', callback: (v) => fmtNum(v) },
          grid: { display: false },
          title: { display: hasLatency, text: t('label_avg_response_ms'), color: '#43534c' },
        },
      },
    },
  });
}

function renderHealthVerdict(health) {
  const box = $('healthVerdict');
  if (!box) return;
  const verdict = health.verdict || 'insufficient_data';
  box.className = 'verdict-banner verdict-' + verdict;
  if (health.available === false) {
    box.innerHTML = `<div class="verdict-title">${t('verdict_table_missing')}</div>`;
    return;
  }
  const parts = [];
  if (health.recent_15m && health.recent_15m.avg_ms !== null) {
    parts.push(t('verdict_recent_avg', { ms: fmtNum(Math.round(health.recent_15m.avg_ms)) }));
  }
  if (health.baseline_24h && health.baseline_24h.avg_ms !== null) {
    parts.push(t('verdict_baseline_avg', { ms: fmtNum(Math.round(health.baseline_24h.avg_ms)) }));
  }
  if (health.latency_ratio !== null && health.latency_ratio !== undefined) {
    parts.push(t('verdict_latency_ratio', { ratio: fmtNum(health.latency_ratio) }));
  }
  box.innerHTML = `<div class="verdict-title">${t('verdict_' + verdict)}</div>` +
    (parts.length ? `<div class="verdict-detail">${parts.join(' · ')}</div>` : '');
}

function renderHealthComparison(cmp) {
  const box = $('healthComparison');
  if (!box) return;
  if (!cmp) { box.innerHTML = ''; return; }
  // More requests isn't an "error" or a "healthy" state by itself - just
  // information - so that delta stays neutral text. A SLOWER average
  // response time is the one that gets colored red/green, since that's the
  // actual good/bad signal this report cares about (see the
  // green-means-active / red-means-error rule the rest of the panel follows).
  const deltaPlain = (pct) => {
    if (pct === null || pct === undefined) return '<span class="muted">—</span>';
    const sign = pct > 0 ? '+' : '';
    return `<span class="muted">(${sign}${fmtPct(pct)})</span>`;
  };
  const deltaLatency = (pct) => {
    if (pct === null || pct === undefined) return '<span class="muted">—</span>';
    const cls = pct > 0 ? 'delta-up' : (pct < 0 ? 'delta-down' : 'muted');
    const sign = pct > 0 ? '+' : '';
    return `<span class="${cls}">(${sign}${fmtPct(pct)})</span>`;
  };
  // Pure rolling durations ending right now - "last 24h" is never a
  // calendar day, and the delta is always against the equal-length period
  // immediately before it (e.g. last 24h vs the 24h before that), so none
  // of this depends on midnight, timezone, or what time it happens to be.
  const rows = [
    [t('comparison_last_24h'), cmp.last_24h, cmp.requests_24h_pct, cmp.latency_24h_pct],
    [t('comparison_last_7d'), cmp.last_7d, cmp.requests_7d_pct, cmp.latency_7d_pct],
    [t('comparison_last_30d'), cmp.last_30d, cmp.requests_30d_pct, cmp.latency_30d_pct],
  ];
  let html = `<table class="health-table"><thead><tr>
      <th>${t('comparison_period')}</th><th>${t('comparison_requests')}</th><th>${t('comparison_avg_ms')}</th>
    </tr></thead><tbody>`;
  for (const [label, data, reqPct, latPct] of rows) {
    html += `<tr>
      <td>${label}</td>
      <td>${fmtNum(data.requests)} ${reqPct !== null ? deltaPlain(reqPct) : ''}</td>
      <td>${data.avg_ms !== null ? fmtNum(Math.round(data.avg_ms)) + ' ' + t('unit_ms') : '—'} ${latPct !== null ? deltaLatency(latPct) : ''}</td>
    </tr>`;
  }
  html += '</tbody></table>';
  html += `<p class="muted small health-note">${t('comparison_note')}</p>`;
  box.innerHTML = html;
}

function renderHealthSystem(sys) {
  const box = $('healthSystem');
  if (!box) return;
  if (!sys || (!sys.load && !sys.memory)) {
    box.innerHTML = `<p class="muted small">${t('system_unavailable')}</p>`;
    return;
  }
  // Same exact card markup (.card / .label / .value / .sub) as every other
  // stat card in the dashboard, reusing its existing type scale rather than
  // inventing a smaller one just for this row - so these three read as
  // "three more cards", not as a separate, differently-styled widget.
  const cards = [];
  if (sys.load) {
    cards.push([t('system_load_1m_label'), fmtNum(sys.load.load_1m), '']);
    cards.push([t('system_load_5m_label'), fmtNum(sys.load.load_5m), '']);
    cards.push([t('system_load_15m_label'), fmtNum(sys.load.load_15m), '']);
  }
  if (sys.cpu_cores) {
    cards.push([t('system_cpu_cores_label'), fmtNum(sys.cpu_cores), '']);
  }
  if (sys.memory) {
    const sub = `${fmtNum(sys.memory.available_mb)} / ${fmtNum(sys.memory.total_mb)} ${t('unit_mb')}`;
    cards.push([t('system_mem_label'), fmtPct(sys.memory.used_pct), sub]);
  }
  box.innerHTML = cards.length ? cards.map(([label, value, sub]) => `
    <div class="card">
      <div class="label" title="${label}">${label}</div>
      <div class="value">${value}</div>
      ${sub ? `<div class="sub">${sub}</div>` : ''}
    </div>
  `).join('') : `<p class="muted small">${t('system_unavailable')}</p>`;
}

// Shared by the growth chart and the OS chart - both only ever plot whole
// user counts, so the y axis is always forced to integer ticks
// (precision: 0) and always gets an explicit title, since an unlabeled
// vertical axis leaves the reader guessing what the numbers even mean.
function chartBaseOptions(yTitle) {
  return {
    responsive: true,
    plugins: { legend: { labels: { color: '#43534c', font: { family: getComputedStyle(document.body).fontFamily } } } },
    scales: {
      x: { ticks: { color: '#7a8780' }, grid: { color: 'rgba(23,35,30,0.07)' } },
      y: {
        ticks: { color: '#7a8780', precision: 0, callback: (v) => fmtNum(v) },
        grid: { color: 'rgba(23,35,30,0.07)' },
        beginAtZero: true,
        title: { display: true, text: yTitle, color: '#43534c' },
      },
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
      <div class="label" title="${label}">${label}</div>
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
    [t('health_verify_rate'), fmtPct(h.verify_success_rate_pct_window), t('health_verify_sub', { n: fmtNum(h.verify_attempts_window) })],
  ];
  $('healthCards').innerHTML = cards.map(([label, value, sub]) => `
    <div class="card">
      <div class="label" title="${label}">${label}</div>
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

$('searchBtn').addEventListener('click', () => runSearch(1));
$('searchInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') runSearch(1); });

async function runSearch(page) {
  const q = $('searchInput').value.trim();
  const box = $('searchResults');
  if (!q) { box.innerHTML = ''; $('searchPager').innerHTML = ''; return; }
  state.searchPage = page || 1;
  box.innerHTML = `<div class="empty-state">${t('searching')}</div>`;
  try {
    const params = new URLSearchParams({ q, page: String(state.searchPage), page_size: '50' });
    const data = await api('admin_search.php?' + params.toString());
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
        <td>${escapeHtml(fmtDateTime(r.last_seen_at))}</td>
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
        <td>${escapeHtml(fmtDateTime(r.first_seen_at))}</td>
        <td>${escapeHtml(fmtDateTime(r.last_seen_at))}</td>
        <td>${r.banned ? `<span class="badge banned">${t('badge_banned')}</span>` : `<span class="badge ok">${t('badge_free')}</span>`}</td>
        <td><button class="btn small ${r.banned ? '' : 'danger'}" data-ban-free="${escapeHtml(r.machine_id || '')}" data-device-hash="${escapeHtml(r.device_public_key_hash || '')}" data-action="${r.banned ? 'unban' : 'ban'}">${r.banned ? t('action_unban') : t('action_ban')}</button></td>
      </tr>`);
    }
    rowsHtml.push('</tbody></table></div>');
  }

  if (data.rejected_devices && data.rejected_devices.length) {
    rowsHtml.push(`<h3 class="small muted">${t('rejected_installs_title')}</h3>`);
    rowsHtml.push('<div class="table-wrap"><table><thead><tr>' +
      `<th>${t('th_machine_id')}</th><th>${t('th_os')}</th><th>${t('th_last_reason')}</th><th>${t('th_build')}</th><th>${t('th_first_seen')}</th><th>${t('th_last_seen')}</th><th>${t('th_ban')}</th><th></th>` +
      '</tr></thead><tbody>');
    for (const r of data.rejected_devices) {
      rowsHtml.push(`<tr>
        <td>${escapeHtml((r.machine_id || '').slice(0, 16))}…</td>
        <td>${escapeHtml(r.platform_profile || '-')}</td>
        <td>${escapeHtml(rejectedReasonLabel(r.last_reason))}</td>
        <td>${escapeHtml(r.last_build_id || '-')}</td>
        <td>${escapeHtml(fmtDateTime(r.first_seen_at))}</td>
        <td>${escapeHtml(fmtDateTime(r.last_seen_at))}</td>
        <td>${r.banned ? `<span class="badge banned">${t('badge_banned')}</span>` : `<span class="badge ok">${t('badge_free')}</span>`}</td>
        <td><button class="btn small ${r.banned ? '' : 'danger'}" data-ban-free="${escapeHtml(r.machine_id || '')}" data-device-hash="${escapeHtml(r.device_public_key_hash || '')}" data-action="${r.banned ? 'unban' : 'ban'}">${r.banned ? t('action_unban') : t('action_ban')}</button></td>
      </tr>`);
    }
    rowsHtml.push('</tbody></table></div>');
  }

  if (!rowsHtml.length) {
    box.innerHTML = `<div class="empty-state">${t('nothing_found')}</div>`;
    $('searchPager').innerHTML = '';
    return;
  }
  box.innerHTML = rowsHtml.join('');
  // Only one of the two lists is ever realistically large at once (an
  // email search only ever matches licenses; a machine-id/device-hash
  // search matches at most one row per table) - one shared pager driven by
  // whichever total is bigger covers both in practice.
  const total = Math.max(data.licenses_total || 0, data.free_devices_total || 0);
  renderPager('searchPager', data.page || 1, total, data.page_size || 50, runSearch);

  box.querySelectorAll('[data-ban-license]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const licenseId = btn.getAttribute('data-ban-license');
      const action = btn.getAttribute('data-action');
      let reason = null;
      if (action === 'ban') reason = prompt(t('ban_reason_prompt')) || '';
      try {
        await api('admin_ban.php', { method: 'POST', body: JSON.stringify({ action, scope: 'license', license_id: Number(licenseId), reason }) });
        runSearch(state.searchPage);
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
        runSearch(state.searchPage);
        loadBannedList();
      } catch (e) { alert(t('error_prefix') + e.message); }
    });
  });
}

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ------------------------------------------------------------- Banned ----

$('refreshBannedBtn').addEventListener('click', () => loadBannedList(1));

async function loadBannedList(page) {
  state.bannedPage = page || state.bannedPage || 1;
  const box = $('bannedList');
  box.innerHTML = `<div class="empty-state">${t('loading')}</div>`;
  try {
    const params = new URLSearchParams({ scope: 'banned', page: String(state.bannedPage), page_size: '50' });
    const data = await api('admin_search.php?' + params.toString());
    if (!data.banned || !data.banned.length) {
      box.innerHTML = `<div class="empty-state">${t('nobody_banned')}</div>`;
      $('bannedPager').innerHTML = '';
      return;
    }
    const rows = data.banned.map((b) => `<tr>
      <td>${escapeHtml(b.scope)}</td>
      <td>${escapeHtml(b.user_email || '-')}</td>
      <td>${escapeHtml((b.machine_id || '').slice(0, 16))}${b.machine_id ? '…' : '-'}</td>
      <td>${escapeHtml(b.reason || '-')}</td>
      <td>${escapeHtml(fmtDateTime(b.banned_at))}</td>
      <td><button class="btn small" data-unban="${b.id}" data-scope="${escapeHtml(b.scope)}" data-license="${b.license_id || ''}" data-machine="${escapeHtml(b.machine_id || '')}" data-device="${escapeHtml(b.device_public_key_hash || '')}">${t('action_unban')}</button></td>
    </tr>`).join('');
    box.innerHTML = `<div class="table-wrap"><table><thead><tr>
      <th>${t('th_type')}</th><th>${t('th_email')}</th><th>${t('th_machine_id')}</th><th>${t('th_reason')}</th><th>${t('th_ban_date')}</th><th></th>
    </tr></thead><tbody>${rows}</tbody></table></div>`;
    renderPager('bannedPager', data.page || 1, data.total || data.banned.length, data.page_size || 50, loadBannedList);

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

// Shared pager widget - used by the -2 log, user search and banned list.
// pagerElId: the container to render prev/page/next into. onPage(n) is
// called with the 1-based page number to load.
function renderPager(pagerElId, page, total, pageSize, onPage) {
  const el = $(pagerElId);
  if (!el) return;
  if (total <= pageSize) { el.innerHTML = ''; return; }
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const prevId = pagerElId + 'PrevBtn';
  const nextId = pagerElId + 'NextBtn';
  el.innerHTML = `
    <button class="btn small" id="${prevId}" ${page <= 1 ? 'disabled' : ''}>${t('prev')}</button>
    <span>${t('page_of', { page, total: totalPages, rows: fmtNum(total) })}</span>
    <button class="btn small" id="${nextId}" ${page >= totalPages ? 'disabled' : ''}>${t('next')}</button>
  `;
  const prevBtn = $(prevId);
  const nextBtn = $(nextId);
  if (prevBtn) prevBtn.addEventListener('click', () => onPage(page - 1));
  if (nextBtn) nextBtn.addEventListener('click', () => onPage(page + 1));
}

// Human label for a -2 reason code; unknown/future codes fall back to the raw
// code so a new server-side reason is never shown blank.
function minus2ReasonLabel(code) {
  const map = {
    artifact_mismatch: 'minus2_reason_artifact_mismatch',
    transport_exhausted: 'minus2_reason_transport_exhausted',
    machineid_generation_failed: 'minus2_reason_machineid_failed',
    artifact_check_failed: 'minus2_reason_artifact_check_failed',
    license_file_invalid: 'minus2_reason_license_file_invalid',
    free_checkin_failed: 'minus2_reason_free_checkin_failed',
    server_rejected: 'minus2_reason_server_rejected',
  };
  return map[code] ? t(map[code]) : (code || '-');
}

function renderMinus2(data) {
  const box = $('minus2Results');
  if (!data.rows.length) {
    box.innerHTML = `<div class="empty-state">${t('nothing_found')}</div>`;
    $('minus2Pager').innerHTML = '';
    return;
  }
  const rows = data.rows.map((r) => `<tr>
    <td>${escapeHtml(fmtDateTime(r.occurred_at))}</td>
    <td>${escapeHtml(r.install_kind)}</td>
    <td>${escapeHtml(minus2ReasonLabel(r.reason_code))}</td>
    <td>${escapeHtml(r.user_email || '-')}</td>
    <td>${escapeHtml((r.machine_id || '').slice(0, 16))}${r.machine_id ? '…' : '-'}</td>
    <td>${escapeHtml(r.platform_profile || '-')}</td>
    <td>${escapeHtml(r.reason_detail || '-')}</td>
  </tr>`).join('');
  box.innerHTML = `<div class="table-wrap"><table><thead><tr>
    <th>${t('th_time')}</th><th>${t('th_type')}</th><th>${t('th_cause')}</th><th>${t('th_email')}</th><th>${t('th_machine_id')}</th><th>${t('th_os')}</th><th>${t('th_details')}</th>
  </tr></thead><tbody>${rows}</tbody></table></div>`;
  renderPager('minus2Pager', data.page, data.total, data.page_size, searchMinus2);
}

// ------------------------------------------------- Rejected devices ---

$('rejectedSearchBtn').addEventListener('click', () => searchRejected(1));
$('rejectedQuery').addEventListener('keydown', (e) => { if (e.key === 'Enter') searchRejected(1); });

function rejectedReasonLabel(reason) {
  const key = 'rejected_reason_' + reason;
  return DICT.fa[key] !== undefined ? t(key) : (reason || '-');
}

async function searchRejected(page) {
  state.rejectedPage = page;
  const q = $('rejectedQuery').value.trim();
  const reason = $('rejectedReason').value;
  const box = $('rejectedResults');
  box.innerHTML = `<div class="empty-state">${t('searching')}</div>`;
  try {
    const params = new URLSearchParams({ page: String(page), page_size: '50', days: '30' });
    if (q) params.set('q', q);
    if (reason) params.set('reason', reason);
    const data = await api('admin_rejected.php?' + params.toString());
    renderRejected(data);
  } catch (e) {
    box.innerHTML = `<div class="empty-state">${t('error_prefix')}${e.message}</div>`;
  }
}

function renderRejected(data) {
  const box = $('rejectedResults');
  const sm = data.summary || {};
  $('rejectedSummary').textContent = t('rejected_summary', {
    banned: fmtNum(sm.banned || 0),
    update_required: fmtNum(sm.update_required || 0),
    artifact_mismatch: fmtNum(sm.artifact_mismatch || 0),
  });
  if (!data.rows.length) {
    box.innerHTML = `<div class="empty-state">${t('nothing_found')}</div>`;
    $('rejectedPager').innerHTML = '';
    return;
  }
  const rows = data.rows.map((r) => `<tr>
    <td>${escapeHtml(fmtDateTime(r.last_seen_at))}</td>
    <td>${escapeHtml(rejectedReasonLabel(r.last_reason))}</td>
    <td>${escapeHtml(t('counts_banned'))} ${fmtNum(r.banned_count)} · ${escapeHtml(t('counts_outdated'))} ${fmtNum(r.update_required_count)} · ${escapeHtml(t('counts_tampered'))} ${fmtNum(r.artifact_mismatch_count)}</td>
    <td>${escapeHtml((r.machine_id || '').slice(0, 16))}${r.machine_id ? '…' : '-'}</td>
    <td>${escapeHtml(r.platform_profile || '-')}</td>
    <td>${escapeHtml(r.last_build_id || '-')}</td>
    <td>${escapeHtml(r.last_observed_ip || '-')}</td>
    <td>${escapeHtml(fmtDateTime(r.first_seen_at))}</td>
    <td>${r.banned ? `<span class="badge banned">${t('badge_banned')}</span>` : ''}</td>
  </tr>`).join('');
  box.innerHTML = `<div class="table-wrap"><table><thead><tr>
    <th>${t('th_last_seen')}</th><th>${t('th_last_reason')}</th><th>${t('th_counts')}</th><th>${t('th_machine_id')}</th><th>${t('th_os')}</th><th>${t('th_build')}</th><th>${t('th_ip')}</th><th>${t('th_first_seen')}</th><th>${t('th_ban')}</th>
  </tr></thead><tbody>${rows}</tbody></table></div>`;
  renderPager('rejectedPager', data.page, data.total, data.page_size, searchRejected);
}

// ------------------------------------------------------------- Startup ---

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js').catch(() => {});
}

checkSession();
