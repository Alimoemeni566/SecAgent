<div align="center">

# 🛡️ SecAgent

### تحلیل‌گر امنیتی چندزبانه کد

**پیدا کردن آسیب‌پذیری‌ها + تولید خودکار کد اصلاح‌شده**

[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4?style=flat-square&logo=dotnet)](https://dotnet.microsoft.com)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D4?style=flat-square&logo=windows)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.0.0-blue?style=flat-square)](https://github.com/Alimoemeni566/SecAgent/releases)

**ساخته‌شده توسط [علی مؤمنی](https://github.com/Alimoemeni566)**

</div>

---

## 📖 درباره پروژه

**SecAgent** یک ابزار رومیزی (Desktop) برای **تحلیل استاتیک امنیتی کد** است که به‌صورت **کاملاً آفلاین** کار می‌کند. کد شما هرگز به سرور خارجی ارسال نمی‌شود.

### ✨ ویژگی‌های کلیدی

- 🌐 **پشتیبانی از ۷ زبان**: C#، Python، JavaScript، TypeScript، PHP، HTML، CSS
- 🔍 **۷ قانون امنیتی**: SQL Injection، Command Injection، XSS، Hardcoded Secret، Weak Crypto، Insecure Random، Empty Catch
- 🔧 **Auto-Fix هوشمند**: تولید نسخه اصلاح‌شده فایل‌ها به‌صورت خودکار
- 🎨 **رابط کاربری مدرن**: تم تیره حرفه‌ای با فیلتر و جستجو
- 🔒 **۱۰۰٪ آفلاین**: بدون ارسال هیچ داده‌ای به بیرون
- 📦 **بدون وابستگی خارجی**: همه چیز با .NET خالص
- 📊 **گزارش JSON**: خروجی ساختاریافته برای مستندسازی
- ⚡ **سریع و سبک**: تحلیل هزاران خط کد در چند ثانیه

---

## 🚀 شروع سریع

### پیش‌نیاز

- **ویندوز ۱۰ یا ۱۱** (64-bit)
- **.NET 10 SDK** (فقط برای ساخت از سورس)

### نصب

#### روش ۱: دانلود فایل اجرایی (توصیه‌شده)

1. به بخش [Releases](https://github.com/Alimoemeni566/SecAgent/releases) بروید
2. آخرین نسخه `SecAgent-v2.0-win-x64.zip` را دانلود کنید
3. فایل را استخراج کنید
4. `SecAgent.exe` را دابل‌کلیک کنید — تمام!

**نیازی به نصب .NET نیست.**

#### روش ۲: ساخت از سورس

```bash
git clone https://github.com/Alimoemeni566/SecAgent.git
cd SecAgent
dotnet build src/SecAgent.Desktop/SecAgent.Desktop.csproj
dotnet run --project src/SecAgent.Desktop