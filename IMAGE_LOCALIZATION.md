# تنزيل صور شروحات المختبرات محلياً — `download_images.py`

سكربت Python 3 يجعل مستودع الشروحات مستقلاً عن الإنترنت من ناحية الصور:
يبحث في كل ملفات Markdown، ينزّل كل صورة خارجية إلى مجلد `images/` المجاور
لملف الشرح الذي يستخدمها، ثم يعيد كتابة روابط الصور فقط لتشير إلى النسخ المحلية.

```
Portswigger_labs/
├── API testing/
│   └── Exploiting a mass assignment vulnerability/
│       ├── README.md          #  ![image](images/image-001.png)
│       └── images/
│           ├── image-001.png
│           └── image-002.png
└── Access Control/
    └── Unprotected admin functionality/
        ├── README.md
        └── images/
            ├── image-001.png
            └── image-002.png
```

---

## 1) المتطلبات والتثبيت

* Python 3.8 أو أحدث (تم الاختبار على 3.11).
* مكتبة واحدة فقط: [`requests`](https://pypi.org/project/requests/).
* يعمل على Linux / Debian وأي نظام آخر يدعم Python.

```bash
sudo apt update && sudo apt install -y python3 python3-pip ca-certificates

# الطريقة المفضلة (بيئة افتراضية، تتوافق مع Debian/Ubuntu الحديثة)
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# أو على مستوى النظام
pip3 install --user requests
# أو من مستودع Debian
sudo apt install python3-requests
```

---

## 2) التشغيل

```bash
# المعالجة الفعلية لمستودع كامل
python3 download_images.py /path/to/Portswigger_labs

# معاينة فقط: لا تنزيل ولا تعديل
python3 download_images.py /path/to/Portswigger_labs --dry-run

# فحص المستودع بعد المعالجة (وضع التحقق)
python3 download_images.py /path/to/Portswigger_labs --check
```

### الخيارات

| الخيار | الافتراضي | المعنى |
| --- | --- | --- |
| `repo` | — | مسار المستودع (إلزامي) |
| `--dry-run` | معطّل | عرض ما سيحدث دون تنزيل أو تعديل أي ملف |
| `--check` | معطّل | وضع الفحص: التحقق من عدم بقاء روابط خارجية، ومن سلامة كل الصور المحلية |
| `--workers N` | `8` | عدد التنزيلات المتوازية (بين 1 و 32) |
| `--timeout S` | `30` | مهلة طلب HTTP بالثواني (اتصال + قراءة) |
| `--retry N` | `3` | عدد المحاولات الإضافية عند الأخطاء المؤقتة (Exponential Backoff + `Retry-After`) |
| `--overwrite` | معطّل | إعادة تنزيل الصور الموجودة أصلاً |
| `--no-backup` | معطّل (أي: النسخ الاحتياطي مفعّل) | تعطيل النسخ الاحتياطية لملفات Markdown |
| `--images-dir NAME` | `images` | اسم مجلد الصور |
| `--exclude NAME` | — | استبعاد مجلد إضافي (قابل للتكرار) |
| `--include GLOB` | — | معالجة ملفات Markdown مطابقة لنمط فقط (قابل للتكرار) |
| `--state-dir PATH` | `<repo>/.image_tool` | مكان الفهرس والنسخ الاحتياطية والتقرير |
| `--report PATH` | `<state-dir>/image_report.json` | مسار تقرير JSON |
| `--max-size BYTES` | `33554432` | أقصى حجم مقبول للصورة (32 MiB) |
| `--max-list N` | `40` | أقصى عدد عناصر تُعرض في كل قائمة |
| `--strict` | معطّل | الخروج بالرمز 1 إذا فشلت أي صورة |
| `--insecure` | معطّل | تعطيل التحقق من شهادة TLS (غير موصى به) |
| `--version` | — | إصدار السكربت |

### رموز الخروج

| الرمز | المعنى |
| --- | --- |
| `0` | نجاح (أو فشل جزئي بدون `--strict`) |
| `1` | فشل بعض الصور مع `--strict`، أو وجود مشاكل في وضع `--check` |
| `2` | خطأ فادح (مسار غير صالح، خطأ غير متوقع) |
| `3` | مكتبة `requests` غير مثبتة |
| `130` | إيقاف يدوي بـ Ctrl+C |

---

## 3) ماذا يفعل بالتفصيل

### اكتشاف الملفات
* المرور التكراري على كامل المستودع (أي عمق) والبحث عن `*.md` و`*.markdown`
  و`*.mdown` و`*.mkd` و`*.mdwn`.
* استبعاد `.git` و`node_modules` و`.venv` و`venv` و`__pycache__` و`dist`
  و`build` ... (القائمة كاملة في `DEFAULT_EXCLUDED_DIRS`)، وكل مجلد يبدأ بنقطة،
  ومجلد الحالة الخاص بالسكربت.
* لا يُنشأ أي مجلد `images/` لمجلد لا يحتوي صوراً.

### أنماط الصور المدعومة
* `![alt](https://...)` مع عنوان اختياري: `![alt](url "title")`.
* روابط بين قوسي زاوية أو تحتوي مسافات/أقواس: `![alt](<https://.../a b.png>)`.
* `<img src="...">` و`<img src='...'>` و`src` غير محاط بقوسين.
* الصور المرجعية: `![alt][ref]` و`![ref][]` و`![ref]` مع تعريف `[ref]: https://...`.
* صور داخل الجداول والقوائم والاقتباسات (`>`) والعناوين — أي موضع خارج الأكواد.

### ما لا يُلمس أبداً
* الأكواد داخل ```` ``` ````/`~~~`، والأكواد المُزاحة بأربع مسافات.
* أكواد Markdown المضمّنة `` `...` ``, وتعليقات `<!-- -->`, و`--- front matter`.
* وسوم `<img>` التي تحمل `onerror`/`onload`/`onclick` — هذه حِمل استغلال
  (XSS/CSRF PoC) وليست صوراً.
* الروابط العادية `[text](https://...)` والمراجع المستخدمة في روابط عادية
  (تُترك تعريفاتها كما هي، وتُضاف للصورة تعريف جديد باسم `local-image-N`).
* كل النصوص البديلة والعناوين والأكواد وترتيب الصور ومحتوى الشرح.

### التنزيل والتحقق
1. متابعة إعادة التوجيه تلقائياً (`301/302/303/307/308`)، بما في ذلك الانتقال
   بين المضيفين (مثل `github.com` ← `user-images.githubusercontent.com`).
2. تجاهل `4xx` نهائياً، وإعادة المحاولة عند `408/429/5xx` بـ Exponential Backoff
   مع احترام `Retry-After` وسقف للمهلة، وتحقّق من المهلة لكل طلب.
3. رفض الاستجابة إن كانت صفحة HTML أو نصاً أو جسم استجابة فارغاً.
4. تحديد الامتداد من توقيع الملف الفعلي (Magic Bytes) لا من الرابط:
   `png, jpg, gif, webp, bmp, tiff, ico, svg, avif, heic`.
5. أسماء متسلسلة وفريدة داخل كل مجلد: `image-001.png`, `image-002.jpg`, ...
   (الاسم النهائي يُحجز بعد معرفة الامتداد، فلا تتصادم الصور مطلقاً).
6. الرابط المتكرر داخل نفس مجلد المختبر يُنزّل مرة واحدة ويُشار إليه عدة مرات.

### الأمان عند الكتابة
* كتابة ذرية: ملف مؤقت في نفس المجلد + `fsync` + `os.replace`، والملف الأصلي
  لا يتأثر إذا توقف السكربت في منتصف التنفيذ.
* نسخة احتياطية لكل ملف Markdown قبل تعديله في
  `.image_tool/backups/<timestamp>/<المسار الأصلي>` — أو `--no-backup` لتعطيلها.
* الاحتفاظ بـ BOM ونوع نهايات الأسطر (LF/CRLF) وبصلاحيات الملف كما هي.
* فهرس `.image_tool/manifest.json` يجعل إعادة التشغيل آمنة: الصور المعروفة
  تُعاد استخدامها دون تنزيل، والروابط المحلية الموجودة لا تُفسد.

---

## 4) التقرير

يُكتب تقرير JSON في `.image_tool/image_report.json` (أو `--report PATH`) ويطبع
ملخّصاً في الطرفية:

```json
{
  "summary": {
    "markdown_files": 177,
    "markdown_with_images": 167,
    "markdown_modified": 166,
    "images_discovered": 981,
    "unique_urls": 959,
    "downloaded": 959,
    "already_present": 0,
    "reused_same_url": 22,
    "failed": 0,
    "links_rewritten": 981
  },
  "failures": [
    {"file": "SSTI/README.md", "line": 12,
     "url": "https://...", "reason": "HTTP 404 Not Found"}
  ],
  "files": [
    {"file": "API testing/.../README.md", "modified": true,
     "images": [{"url": "https://...", "line": 3,
                 "local": "images/image-001.png", "status": "downloaded"}]}
  ]
}
```

الروابط التي فشل تنزيلها **تبقى كما هي** في ملفات Markdown، وتُسجّل هنا بالسبب.

---

## 5) وضع التحقق `--check`

يفحص المستودع كاملاً دون تعديل أي شيء ويبلّغ عن:

1. أي صورة ما زالت تشير إلى رابط خارجي (مع استثناء ما فشل تنزيله سابقاً والمسجّل
   في تقرير التشغيل).
2. أي رابط محلي يشير إلى ملف غير موجود.
3. أي ملف صورة فارغ أو تالف (فحص التوقيع الفعلي وليس الامتداد).
4. ملفات صور غير مشار إليها (معلومة فقط، ليست خطأ).

يعيد الرمز `1` عند وجود مشاكل و`0` عند سلامة المستودع، لذا يصلح للتشغيل في CI:

```bash
python3 download_images.py . --check || echo "المستودع غير مكتمل"
```

---

## 6) سيناريوهات شائعة

```bash
# أول تشغيل على مستودع كبير، بشبكة بطيئة
python3 download_images.py /path/Portswigger_labs --workers 4 --timeout 60 --retry 5

# إعادة المحاولة للصور التي فشلت فقط (الروابط الباقية هي الفاشلة)
python3 download_images.py /path/Portswigger_labs --max-list 100

# تجديد كل الصور من المصدر
python3 download_images.py /path/Portswigger_labs --overwrite

# بدون نسخ احتياطية (مثلاً داخل حاوية مؤقتة)
python3 download_images.py /path/Portswigger_labs --no-backup

# معالجة ملف واحد أو تصنيف واحد فقط
python3 download_images.py . --include "SQL_injection/**"

# خلف وكيل شركة: صدّر شهادة الوكيل لـ requests
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/corporate-ca.pem
```

---

## 7) ملاحظات

* **التعامل مع المصادقة:** لا يحتاج السكربت أي توكن؛ مسارات GitHub المذكورة
  (`/assets/<id>` و`/user-attachments/assets/<id>` و`user-images.githubusercontent.com`)
  تعيد `302` إلى رابط S3 موقّع مؤقتاً، والسكربت يتبع التحويل ويحفظ الملف الفعلي.
* **إذا كان المستودع خلف شبكة تحظر GitHub** فستظهر كل الصور في قسم `Failures`
  مع سبب واضح، ولن يُعدَّل أي ملف Markdown. أعد التشغيل بعد حل الشبكة.
* **لا يوجد اعتماد على أي مكتبة تحليل Markdown خارجية**؛ المحلّل مكتوب داخلياً
  ويهتم فقط بمواضع الصور، لذلك يبقى باقي الملف كما هو بايتاً ببايت.
