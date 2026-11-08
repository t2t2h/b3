# DomainSniffer (Theos)

dylib يراقب اتصالات اللعبة ويسجّل النطاقات والـ IP، مع قائمة عائمة وحفظ.

## ما يلتقطه
- DNS: `getaddrinfo` و `gethostbyname` (يشمل SDK الأصلية مثل Agora / Zego)
- HTTP / رفع / تحميل / WebSocket عبر `NSURLSession`
- اتصالات IP مباشرة: `connect` و `sendto` (UDP)
- يميّز النطاقات المحجوبة من NextDNS (الرد 0.0.0.0 أو ::) بعلامة ⛔، والفاشلة بـ ⚠️

## البناء
```
export THEOS=~/theos
make package
```
الناتج: `packages/*.deb` والملف `.theos/obj/DomainSniffer.dylib`

## الحقن (بدون جيلبريك)
استخدم Sideloadly أو ESign أو Feather لحقن `DomainSniffer.dylib` في الـ IPA.
مهم: فعّل خيار حقن Cydia Substrate / ElleKit لأن الـ dylib يعتمد على `MSHookFunction`.

## الاستخدام
- زر 🌐 عائم قابل للسحب، اضغطه لفتح القائمة.
- بحث + فلتر: الكل / نطاقات / IP / محجوب.
- الضغط على أي سطر ينسخه.
- 💾 حفظ: يكتب الملفات في `Documents/DomainSniffer/`
  - `denylist_nextdns.txt` (النطاقات غير المحجوبة بسطر لكل نطاق، جاهزة للصق في NextDNS)
  - `domains.txt` و `ips.txt` و `data.json`
- 📤 مشاركة: يفتح قائمة المشاركة لحفظ الملفات في تطبيق الملفات.
- 📋 نسخ Denylist: ينسخ قائمة النطاقات للحافظة.
- 🗑 مسح: يحذف السجل.
- السجل يُحفظ تلقائياً كل 5 ثوانٍ ويُحمَّل عند فتح اللعبة مجدداً.
