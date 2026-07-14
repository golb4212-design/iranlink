# IranLink — نصب خیلی ساده

این پروژه فقط **۳ فایل** دارد:

- `README.md`
- `install.sh`
- `iranlink.sh`

هر سه فایل را مستقیم در صفحه اصلی ریپوی GitHub بگذار.

## مرحله ۱: نصب روی سرور خارج

```bash
sudo apt update && sudo apt install -y git
git clone https://github.com/golb4212-design/iranlink.git
cd iranlink
sudo bash install.sh
```

وقتی سؤال پرسید:

```text
1) این سرور خارج است
2) این سرور ایران است
```

عدد `1` را بزن.

در پایان دو چیز نمایش داده می‌شود:

- IP سرور خارج
- Public Key سرور خارج

هر دو را کپی کن.

---

## مرحله ۲: نصب روی سرور ایران

```bash
sudo apt update && sudo apt install -y git
git clone https://github.com/golb4212-design/iranlink.git
cd iranlink
sudo bash install.sh
```

این بار عدد `2` را بزن و فقط این دو مورد را وارد کن:

- IP سرور خارج
- Public Key سرور خارج

در پایان، نصب‌کننده یک دستور آماده می‌دهد؛ شبیه این:

```bash
sudo iranlink peer add PUBLIC_KEY_IRAN
```

همان دستور را کپی کن و **روی سرور خارج** اجرا کن.

---

## مرحله ۳: تست روی سرور ایران

```bash
sudo iranlink test
```

اگر دیدی:

```text
LEAK TEST: OK
```

تونل درست وصل شده و IP ایران نشت نمی‌کند.

---

## اتصال Xray به تونل

روی سرور ایران:

```bash
sudo iranlink service attach xray.service
```

اگر اسم سرویس Xray متفاوت بود:

```bash
systemctl list-units --type=service | grep -i xray
```

بعد نام درست را جای `xray.service` بگذار.

## بازکردن پورت از IP ایران

مثلاً پورت TCP شماره 443:

```bash
sudo iranlink publish tcp 443
```

برای UDP:

```bash
sudo iranlink publish udp 443
```

## دستورهای کاربردی

```bash
sudo iranlink status
sudo iranlink test
sudo iranlink restart
sudo iranlink logs
sudo iranlink show-key
```

## حذف کامل

```bash
sudo iranlink uninstall
```

## نکته مهم

- ترافیک سرویس متصل‌شده داخل Network Namespace جدا اجرا می‌شود.
- اگر تونل قطع شود، Kill Switch اجازه خروج ترافیک خام از IP ایران را نمی‌دهد.
- مقصدهای خصوصی، SMTP مستقیم و تعداد غیرعادی اتصال‌های جدید در سرور خارج محدود می‌شوند.
- هیچ تونلی افت سرعت کاملاً صفر را تضمین نمی‌کند؛ کیفیت دو سرور و مسیر شبکه مهم است.
