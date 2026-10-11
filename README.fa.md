<div align="center">

<img src="docs/screenshots/banner.png" alt="SecAgent" width="100%">

# SecAgent

### تحلیل‌گر امنیتی چندزبانه — با اصلاح خودکار

[![آخرین نسخه](https://img.shields.io/github/v/release/alimoemeni/SecAgent?style=flat-square&color=00D9FF&label=release)](https://github.com/alimoemeni/SecAgent/releases)
[![مجوز](https://img.shields.io/github/license/alimoemeni/SecAgent?style=flat-square&color=green)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4?style=flat-square&logo=dotnet&logoColor=white)](https://dotnet.microsoft.com)
[![پلتفرم](https://img.shields.io/badge/platform-Windows%2010%2B-0078D4?style=flat-square&logo=windows)](https://www.microsoft.com/windows)
[![مشارکت خوش‌آمد](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](CONTRIBUTING.md)

[**English**](README.md) · **فارسی**

</div>

---

## فهرست مطالب

- [چرا SecAgent؟](#چرا-secagent)
- [چه کاری انجام می‌دهد؟](#چه-کاری-انجام-میدهد)
- [تصاویر محیط برنامه](#تصاویر-محیط-برنامه)
- [نصب](#نصب)
- [شروع سریع](#شروع-سریع)
- [نحوه استفاده](#نحوه-استفاده)
- [یک مثال واقعی](#یک-مثال-واقعی)
- [قوانین امنیتی](#قوانین-امنیتی)
- [موتور اصلاح خودکار](#موتور-اصلاح-خودکار)
- [معماری پروژه](#معماری-پروژه)
- [افزودن قانون جدید](#افزودن-قانون-جدید)
- [بنچمارک](#بنچمارک)
- [نقشه راه](#نقشه-راه)
- [سؤالات متداول](#سؤالات-متداول)
- [مشارکت](#مشارکت)
- [مجوز](#مجوز)
- [نویسنده](#نویسنده)

---

## چرا SecAgent؟

سال‌ها شاهد این بودم که توسعه‌دهندگان کدی را منتشر می‌کنند که می‌دانستند ممکن است مشکل داشته باشد — نه به این خاطر که اهمیت نمی‌دادند، بلکه چون ابزارهای موجود یا خیلی گران بودند، یا راه‌اندازی‌شان پیچیده بود، یا می‌خواستند سورس‌کد را به سرور ابری خودشان بفرستند.

SecAgent پاسخ من به این مشکل است. یک **برنامه رومیزی** که کاملاً روی سیستم خودتان اجرا می‌شود، کد شما را برای آسیب‌پذیری‌های رایج امنیتی اسکن می‌کند، و — این بخشی است که بیشتر ابزارها انجام نمی‌دهند — **نسخه اصلاح‌شده فایل‌ها را تولید می‌کند** تا فقط از مشکل باخبر نشوید، بلکه یک قدم جلوتر باشید.

بدون سرور. بدون حساب کاربری. بدون تلمتری. بدون اینکه کد شما از سیستم‌تان خارج شود. هرگز.

---

## چه کاری انجام می‌دهد؟

SecAgent فایل‌های سورس شما را می‌خواند، مجموعه‌ای از قوانین امنیتی را اعمال می‌کند، و یافته‌ها را با سطح خطر، ارجاع CWE، محل دقیق در فایل و قطعه کد گزارش می‌دهد. سپس، برای آسیب‌پذیری‌هایی که توانایی اصلاح دارد، نسخه اصلاح‌شده فایل را تولید می‌کند.

در حال حاضر از **هفت زبان** و **هفت قانون امنیتی** پشتیبانی می‌کند — که با دقت انتخاب شده‌اند تا رایج‌ترین مشکلات کدبیس‌های واقعی را پوشش دهند.

<table>
<tr>
<td valign="top" width="50%">

### زبان‌های پشتیبانی‌شده

- 🟣 **C#** — `.cs`
- 🟡 **Python** — `.py`
- 🟨 **JavaScript** — `.js`، `.mjs`، `.cjs`
- 🔵 **TypeScript** — `.ts`
- 🟪 **PHP** — `.php`، `.phtml`
- 🟠 **HTML** — `.html`، `.htm`
- 🔷 **CSS** — `.css`

</td>
<td valign="top" width="50%">

### قوانین امنیتی

| قانون | CWE |
|------|-----|
| SQL Injection | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) |
| Command Injection | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) |
| Cross-Site Scripting | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| Hardcoded Secrets | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| Weak Cryptography | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) |
| Insecure Randomness | [CWE-338](https://cwe.mitre.org/data/definitions/338.html) |
| Empty Catch Blocks | [CWE-390](https://cwe.mitre.org/data/definitions/390.html) |

</td>
</tr>
</table>

---

## تصاویر محیط برنامه

<div align="center">

### داشبورد
<img src="docs/screenshots/dashboard.png" alt="داشبورد" width="750">

### اسکن جدید
<img src="docs/screenshots/scan.png" alt="صفحه اسکن" width="750">

### نتایج با فیلتر
<img src="docs/screenshots/results.png" alt="صفحه نتایج" width="750">

### اصلاح خودکار — فایل‌های اصلاح‌شده
<img src="docs/screenshots/autofix.png" alt="صفحه اصلاح خودکار" width="750">

</div>

---

## نصب

### روش ۱ — دانلود فایل اجرایی (توصیه‌شده)

۱. به [صفحه Releases](https://github.com/alimoemeni/SecAgent/releases) بروید
۲. آخرین نسخه `SecAgent-vX.X.X-win-x64.zip` را دانلود کنید
۳. هر جایی که خواستید استخراج کنید
۴. روی `SecAgent.exe` دابل‌کلیک کنید

تمام. **بدون نیاز به نصب .NET، بدون installer، بدون دسترسی admin.** فایل اجرایی هر چیزی که لازم دارد را در خود دارد.

> اگر ویندوز SmartScreen هشدار داد، روی **More info** → **Run anyway** کلیک کنید. این برای هر فایل اجرایی جدید بدون گواهی امضای گران‌قیمت اتفاق می‌افتد.

### روش ۲ — ساخت از سورس

```bash
git clone https://github.com/alimoemeni/SecAgent.git
cd SecAgent
dotnet restore
dotnet build src/SecAgent.Desktop/SecAgent.Desktop.csproj -c Release
dotnet run --project src/SecAgent.Desktop