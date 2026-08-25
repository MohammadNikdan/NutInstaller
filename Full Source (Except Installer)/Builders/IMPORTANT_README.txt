=== IMPORTANT README — راهنمای فایل‌های build_*.bat (چیدمان جدید) ===

همۀ بیلدرها فقط در صوتی کار میکنند که همۀ کلیدها به درستی در محل اصلی قرار داشته باشند. بنابراین هیچ کلیدی نباید موجود نبوده یا بدون محتوای یا با محتوای Hidden باشد.


## ساختار پوشه‌ای فعلی (که همهٔ bat ها با همین چیدمان کار می‌کنن)
Full Source (Except Installer)/
├── Builders/          ← همهٔ bat ها اینجا (شما همین الان اینجایید)
│   └── Builds/        ← خروجی build ها همینجا ساخته می‌شود (نه هم‌سطح Builders، بلکه داخلش)
├── Coordinator/
├── LicenseCheck/
├── MachineID/
├── Keys/              ← شامل KeyBaker.exe هم هست
├── PHPs/
└── SignTool/

## پیش‌نیاز
Dev-C++ (نسخهٔ Embarcadero) با TDM-GCC-64 لازم است.

## مسیر کامپایلر که همین الان داخل هر فایل تنظیم شده
```
C:\Program Files (x86)\Embarcadero\Dev-Cpp\TDM-GCC-64\bin\g++.exe
```
اگر این مسیر عوض شد: هر فایل `.bat` را با Notepad باز کنید، خط
`set GPP32=...` یا `set GPP64=...` را پیدا کنید و مسیر جدید را جایگزین کنید.

## ترتیب پیشنهادی اجرا
۱. `build_KeyBaker.bat` (فقط یک‌بار — یا هر وقت خود KeyBaker.cpp تغییر کرد)
۲. بعد از آن، هر کدام از این‌ها را در هر ترتیبی که خواستید:
   `build_LicenseCheck_x86/x64.bat`
   `build_Service_x86/x64.bat`
   `build_Broker_x86/x64.bat`
   `build_MachineId_x86/x64.bat`
   `build_SignTool.bat`

هرکدام از این‌ها (به‌جز KeyBaker) خودشان قبل از کامپایل، KeyBaker.exe را
اجرا می‌کنند تا کلیدهای Keys/ به‌روز باشند - نیازی نیست دستی صداش بزنید.

## نکتهٔ مهم دربارهٔ نسخهٔ ۳۲‑بیتی
چون فقط یک کامپایلر (TDM-GCC-64) دارید، فایل‌های `_x86.bat` از همان
کامپایلر با فلگ `-m32` استفاده می‌کنند. اگر با خطای
`cannot open linker script file ldscripts/i386pe.x` مواجه شدید، یعنی این
نسخهٔ TDM-GCC-64 شما multilib نیست — باید یک کامپایلر جدا و مخصوص
۳۲‑بیتی نصب کنید و مسیرش را در `GPP32` بگذارید (و خط `-m32` را حذف کنید).

## یادآوری برای Service، Broker، و SignTool
قبل از اجرای این‌ها، حتماً باید فایل‌های حساس در `Keys\` (به‌خصوص
`CoordinatorIdentityKey_Private.pem`، `TransportKey.txt`، و
`VendorSigningKey_Private.pem`) مقدار واقعی داشته باشند — نه خالی. جزئیات
کامل در `Keys\README.txt`.
