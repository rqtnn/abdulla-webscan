# Abdulla WebScan

## الفحص التلقائي الموسّع — 1.1

الحين تدخل IP واحد، والأداة تمشي من اكتشاف الخدمات إلى فحوص الويب، ثم crawling
للصفحات والمسارات المكتشفة، وجمع GET parameters وتشغيل SQLmap detection تلقائياً.
تشغّل Nuclei مرة ثانية على قائمة الروابط المكتشفة. التقرير يجمع حالة التغطية،
النتائج حسب درجة الخطورة المبلّغ عنها، الأدلة، والخطوات المقترحة للتحقق والمعالجة.
هذا تقييم ويب غير مسجل الدخول، وليس بديلاً مكافئاً لتغطية Nessus للأنظمة والشبكات.

```bash
# اكتشاف الخدمات، crawling وفحوص الباراميترات تلقائياً
python3 webscan.py 192.168.56.101

# جميع بورتات TCP وتغطية crawling أكبر ضمن اللاب
python3 webscan.py 192.168.56.101 --all-ports --nmap-timeout 3600 \
  --crawl-pages 300 --crawl-depth 5 --crawl-timeout 600 \
  --max-sqli-jobs 20 --sqli-timeout 180 --rate 3

# جمع الروابط والباراميترات بدون SQLmap التلقائي
python3 webscan.py 192.168.56.101 --no-auto-sqli

# تعطيل crawling والفحوص الناتجة عنه
python3 webscan.py 192.168.56.101 --no-crawl
```

الحدود الافتراضية: 100 طلب crawling، عمق 3، ميزانية 120 ثانية، و10 فحوص
URL/parameter كحد أقصى، بمهلة 120 ثانية لكل فحص SQLmap. المهلة تعتمد أيضاً على
مهل الاتصال والقراءة؛ ليست موعداً مضموناً بالثانية. أقصى الخيارات المسموحة:
1000 طلب، عمق 10، و50 فحص SQLmap. كل فحص باراميتر له وقت مستقل، لذلك وقت التشغيل
الإجمالي قد يطول. فحوص SQLmap التلقائية بالتتابع حتى لو اخترت parallel.

Crawler يتبع روابط HTML داخل نفس IP والبورت/scheme الذي استجاب في discovery فقط.
لا يتبع redirects ولا يشغّل JavaScript. يحتفظ بجسم الاستجابة حتى 256 KiB،
headers، status، URL وSHA-256؛ ويكتب حدود العمق والوقت والطلبات والأخطاء.
يجمع بحد أقصى عشرة أضعاف عدد الطلبات من الروابط، ويزور ثلاث قيم مختلفة كحد أقصى
لنفس المسار ومجموعة أسماء الباراميترات لتقليل دوائر crawling.

GET forms البسيطة تُسجل بقيم input الموجودة (أو الفارغة)، بدون إرسالها أثناء crawling؛
قد تُستخدم لاحقاً في فحوص SQLmap وNuclei. POST forms وحقول password/file وselect/textarea
تُترك للمراجعة اليدوية. الروابط التي تبدو كعمليات logout/delete/reset/شراء
تُستبعد آلياً كاحتياط تقريبي؛ هذا لا يضمن أن كل GET خالٍ من الآثار الجانبية.
الباراميترات الحساسة أو المكررة والنتائج التي تجاوزت الحد تسجل بأسباب استبعادها.
يختار URL واحداً لكل origin/path/مجموعة أسماء باراميترات واسم باراميتر، ولا يفحص
كل قيمة مكررة. اكتشاف باراميتر يعني أنه مرشح للفحص، وليس أنه قابل للحقن فعلاً.

SQLmap يستخدم level 1 / risk 1 وBEU detection، بدون database dump أو OS shell.
يحفظ الطلبات والاستجابات في `traffic.log` مع console وsession. راجع
[SQLmap usage](https://github.com/sqlmapproject/sqlmap/wiki/Usage).
Nuclei يستخدم قوالب HTTP المحلية الموسومة tech/misconfig/exposure/cve مع استثناء
dos/fuzz/bruteforce/intrusive/headless/code؛ وجود CVE ضمن القوالب لا يعني فحص جميع CVEs.
راجع [Nuclei documentation](https://docs.projectdiscovery.io/opensource/nuclei/running).
فحوص headers السلبية تسجل غياب CSP وX-Content-Type-Options، وHSTS على HTTPS،
كملاحظات منخفضة الخطورة تحتاج تحقق وليست إثبات استغلال.

الملفات الجديدة: `crawl/crawl.json`، `crawl/urls.txt`، `crawl/body-*.bin`،
`discovered/web-01/nuclei/` و`auto-sqli/<number>/`.
`summary.json` يضيف `crawl` و`injection` و`coverage`. `--dry-run` لا يجمع روابط
فعلية؛ يظهر مراحل الاكتشاف كخطط، لذلك لا يخترع أوامر فحص لباراميترات لم يكتشفها.
Exit code 2 يشمل أيضاً حدود crawling، أخطاءه، الاستجابات المقتطعة، والباراميترات
المستبعدة من SQLmap. هذه فجوات تغطية، لا إعلان بأن الهدف آمن أو مصاب.

## Unified findings report (updated)

`report.html` now includes deduplicated observations and parsing/manual-review gaps.
`summary.json` contains `report_schema_version: 2`, `findings`, and `parse_issues`.
Every finding has `validation_status: needs_validation`; severity is the scanner's
label, not an independently assessed severity or CVSS score. HTTP endpoints and
technology observations are not automatically vulnerabilities.

Supported adapters: FFUF JSON, Gobuster text, Feroxbuster response JSONL,
Dirsearch flat `results` JSON (0.4.3 format), WhatWeb JSON, HTTPx JSONL,
Nikto JSON (single host or host array), Nuclei JSONL, and SQLmap console GET
Type/Title/Payload blocks, plus built-in crawling and passive header checks.
Nmap XML remains in the open-services table.
SQLmap session files still require manual review. Other versions may produce
different formats; unsupported/malformed records are shown in `parse_issues`.

Deduplication merges identical HTTP endpoints/statuses across directory scanners.
Distinct vulnerability checks, matcher names, HTTP methods (Nikto), queries,
paths, schemes, ports and status codes stay separate. Explicit default ports
normalize to the same URL. Cross-scanner vulnerability matches are deliberately
kept separate because similarity alone does not establish equivalence.
Each finding retains all contributing records, tool/job status, source file,
record index (line number for JSONL/text), and SHA-256 of the original file.
Raw files, commands, console logs, and SQLmap sessions remain on disk.
Failed/timed-out jobs may contribute partial evidence. A parsing gap is visible
in the report but does not change the existing process/coverage exit codes.
Keep the entire run folder when sharing or archiving evidence. Scanner output
can include sensitive requests/responses; the report is generated locally.

Validate each candidate in your authorized lab: check the exact URL/request,
reproduce the observed behavior, compare with a control request, and record the
outcome separately. This release does not promote candidates to confirmed findings.

## Windows: run inside Kali WSL

In an Administrator PowerShell window:

```powershell
wsl --install -d kali-linux
```

Restart Windows if requested, launch Kali, and finish creating your Linux user.
See [Microsoft's WSL installation guide](https://learn.microsoft.com/en-us/windows/wsl/install)
and [Kali's WSL guide](https://www.kali.org/blog/kali-linux-modern-wsl/).
Then inside Kali's Linux shell:

```bash
sudo apt update
sudo apt install python3 nmap whatweb ffuf gobuster feroxbuster dirsearch nikto nuclei sqlmap httpx-toolkit
nuclei -ut
cd /mnt/d/Codex/abdulla-webscan
python3 webscan.py --check
python3 -m unittest discover -s tests -v
python3 webscan.py 192.168.56.101 --dry-run --ports 80,443
python3 webscan.py 192.168.56.101 --ports 80,443 --enum ffuf --rate 3
```

Replace the example IP with your single authorized lab IP. Ensure it is reachable
from WSL/Kali; localhost inside WSL refers to that Linux environment. A Kali VM
can use the same commands from the directory where you copied the project.
If a package is unavailable, use its official installation instructions or
`--skip`; missing tools are recorded as coverage gaps. No Python packages are needed.
Open the resulting `results/<run>/report.html` in your Windows browser via Explorer
at `D:\Codex\abdulla-webscan\results`. The CLI still requires Linux/Kali/WSL.
Offline report adapter tests can also run with native Windows Python; five CLI,
process-group, and executable-fixture tests explicitly skip there and must run
in Linux to verify the full workflow.

أداة شخصية تجمع فحوص الويب من **IP واحد** وتكتب النتائج في تقرير HTML وJSON.
تعمل على **Kali / Linux / WSL مع Python 3.10 أو أحدث**، بدون مكتبات Python إضافية.
استخدم عنوان اللاب المصرّح لك تختبره.

## تثبيت الأدوات على Kali — مرة واحدة

```bash
sudo apt update
sudo apt install python3 nmap whatweb ffuf gobuster feroxbuster dirsearch nikto nuclei sqlmap httpx-toolkit
nuclei -ut
```

الأداة نفسها لا تثبّت أي برنامج ولا تعمل updates تلقائياً. تحتاج اتصال إنترنت للتثبيت
وتنزيل قوالب Nuclei فقط. هذا المشروع لا يعيد توزيع برامج الفحص أو قوالبها.
`httpx-toolkit` هو اسم أداة ProjectDiscovery في Kali؛ مكتبة Python المسماة `httpx`
شيء مختلف. السكربت يفحص هذا الفرق ويتخطى الأداة إذا وجد النسخة الخطأ.
لو أي package غير متوفر في مستودعك، ثبّت الأداة من مصدرها الرسمي أو استخدم `--skip`.

فك ZIP وادخل المجلد ثم تحقق من الأدوات:

```bash
cd abdulla-webscan
python3 webscan.py --check
```

## أبسط تشغيل

```bash
python3 webscan.py 192.168.56.101
```

بدون IP سيطلبه منك:

```bash
python3 webscan.py
```

يبدأ بـ Nmap، يقرأ البورتات المفتوحة، يجرّب HTTP/HTTPS على خدمات الويب، وبعدها يشغّل:

| المرحلة | العمل |
|---|---|
| Nmap | TCP connect + service/version detection، أول 1000 بورت شائع افتراضياً |
| HTTP discovery | طلب GET لكل URL محتمل؛ يسجل status، title، server، والـredirect بدون اتباعه |
| ProjectDiscovery HTTPx | معلومات HTTP وتقنيات الموقع، إذا مثبت |
| WhatWeb | التعرف على التقنيات بمستوى aggression 1 |
| Directory enumeration | يختار أول أداة مثبتة: FFUF ثم Gobuster ثم Feroxbuster ثم Dirsearch |
| Nikto | فحوص الملفات والإعدادات وكشف المعلومات والتعرف على البرمجيات، tuning 123b |
| Nuclei | قوالب HTTP المحلية tech / misconfig / exposure / cve مع exclusions محددة، وعلى الروابط المكتشفة أيضاً |
| Crawling | روابط HTML وGET forms البسيطة ضمن خدمات نفس الـIP المستجيبة؛ أدلة وحدود تغطية |
| SQLmap | تلقائياً على GET parameters المكتشفة ضمن الحدود، أو على URL وparameter تحددهما أنت |
| Burp Suite | يدوي؛ افتح الموقع واختبر الـrequests والصلاحيات ومنطق التطبيق |

الأداة تتخطى البرنامج الناقص وتكتب السبب، وتكمل بقية الفحوص. إذا غاب Nmap أو لم يعط
بورتات مفتوحة، تجرّب بورتات ويب شائعة؛ إن حددت `--ports` فلن تخرج هذه المحاولات عن قائمتك.
لا يحتاج السكربت root لأن Nmap يستخدم `-sT`. لا يستخدم `-sC` أو exploitation NSE scripts.

## بالتتابع أو مع بعض

افتراضياً الفحوص بالتتابع. للتوازي بعد انتهاء Nmap وHTTP discovery:

```bash
python3 webscan.py 192.168.56.101 --mode parallel --workers 2
```

لتشغيل أدوات المسارات الأربع بدلاً من اختيار واحدة:

```bash
python3 webscan.py 192.168.56.101 --mode parallel --enum all
```

تشغيل الأربع يكرر كثيراً من الطلبات. غالباً أداة واحدة تكفي:

```bash
python3 webscan.py 192.168.56.101 --enum ffuf
python3 webscan.py 192.168.56.101 --enum feroxbuster
```

## خيارات مفيدة

```bash
# معاينة الأوامر؛ بدون network requests أو تشغيل البرامج
python3 webscan.py 192.168.56.101 --dry-run --ports 80,443

# تحديد البورتات
python3 webscan.py 192.168.56.101 --ports 80,443,3000,8080

# جميع بورتات TCP؛ قد يستغرق وقتاً أطول
python3 webscan.py 192.168.56.101 --all-ports --nmap-timeout 3600

# موقع على بورت غير معتاد أو مسار أساسي معين
python3 webscan.py 192.168.56.101 --url http://192.168.56.101:5001/app/

# لاب بشهادة HTTPS ذاتية التوقيع
python3 webscan.py 192.168.56.101 --insecure

# قائمة مسارات أكبر محلية؛ لا تقرأ wordlist من URL
python3 webscan.py 192.168.56.101 --wordlist /usr/share/wordlists/dirb/common.txt

# تخطي أدوات
python3 webscan.py 192.168.56.101 --skip nikto nuclei

# تقليل المعدل وتحديد وقت كل أداة
python3 webscan.py 192.168.56.101 --rate 3 --tool-timeout 300
```

القائمة المرفقة صغيرة (33 مساراً)، مناسبة لفحص بداية سريع. استبدلها بقائمة أكبر
لتوسيع التغطية. لا توجد recursion افتراضياً في enumerators. إذا كان Nmap لا يميز
خدمة ويب على بورت غير شائع، أدخل `--url` لذلك البورت.

`--rate` هو سقف تقريبي **لكل أداة**، وليس سقفاً لجميع الطلبات. في التوازي تجتمع
معدلات الأدوات. طلبات discovery وفحوص الخدمة في Nmap مستقلة عنه.
`--tool-timeout` حد لكل job؛ ليس وقتاً إجمالياً للبرنامج. Ctrl+C يوقف العمليات
التابعة ويكتب تقريراً بالنتائج المتاحة. بعض الأدوات تنهي نفسها عند حدها الداخلي
بـexit code صفر؛ راجع logs لمعرفة إن اكتمل الفحص فعلاً.

## SQLmap

Crawler يبحث عن GET parameters تلقائياً. لتحديد صفحة غير مرتبطة أو باراميتر معين مثل `product.php?id=1`:

```bash
python3 webscan.py 192.168.56.101 \
  --sqlmap-url 'http://192.168.56.101/product.php?id=1' \
  --sqlmap-param id
```

هذا يشغّل detection على الـGET parameter المحدد بـlevel 1 / risk 1، باستخدام
Boolean، Error، وUNION techniques. لا يستخرج قواعد البيانات أو الجداول، ولا يشغّل
OS shell. لا يشمل POST/JSON requests أو authenticated flows في هذه النسخة.
الـURL لازم يستعمل نفس IP. SQLmap التلقائي يفحص الباراميترات المختارة ضمن الحدود، ولا يفحص كل مسار أو قيمة.

## التقرير

كل تشغيل يكتب مجلداً جديداً تحت `results/`:

- `report.html`: افتحه بالمتصفح؛ جدول البورتات، استجابات الويب، وحالة كل فحص وروابط نتائجه.
- `summary.json`: معلومات التشغيل والنتائج والحالات بشكل قابل للمعالجة.
- `urls.txt`: خدمات HTTP/HTTPS التي استجابت.
- `nmap/services.xml`: نتائج الخدمات.
- داخل مجلد كل أداة: `command.txt` و`console.log` وملف النتائج إن أنتجته الأداة.

حالات التشغيل: `completed`، `skipped`، `failed`، `timeout`، `cancelled`، `planned`، و`limited` للـcrawler.
السكربت **لا يعتبر خروج البرنامج بنجاح إثباتاً أن الموقع آمن**. التقرير يجمع الأدلة
والمخرجات الخام؛ النتائج المرشحة تحتاج تحقق يدوي، ولا يعيّن CVSS تلقائياً.
Exit codes: `0` تشغيل بلا فجوات ظاهرة أو dry-run، `2` نقص تغطية/خطأ إعدادات، `130` إيقاف.

## حدود النسخة

- IP واحد IPv4. لا يدعم hostname / IPv6 / IP ranges أو multi-target scans.
- مواقع virtual hosting أو SNI التي تحتاج domain قد لا تظهر بشكل صحيح عبر IP.
- لا يختبر login، IDOR، business logic أو كل XSS تلقائياً؛ استعمل Burp للخطوات اليدوية.
- Nuclei يستخدم `~/nuclei-templates`؛ غيّر المكان بـ`--templates` إذا لزم.
- قوالب Nuclei والأدوات وإصداراتها تحدد مدى التغطية. هذه ليست كل قوالب CVE ولا كل
  فئات Nikto. يمكن أن تكتشف هذه الإعدادات كشف معلومات وإعدادات خاطئة وتقنيات فقط.
- discovery لا يتبع redirects، والسكربت يعطلها في WhatWeb وNuclei وSQLmap، ولا يفعّل
  اتباعها في enumerators. هذا تنظيم لأهداف الإدخال، وليس network sandbox: إعدادات
  الأدوات المحلية وقوالبها قد تغير سلوكها، فاستعمل نسخاً وقوالباً موثوقة ضمن اللاب.
- Nuclei OAST/update checks معطلة وقت الفحص. السكربت لا يرفع النتائج لأي خدمة.
- التحقق من شهادة TLS يتم في discovery؛ بعض أدوات الفحص نفسها تتعامل مع TLS
  بطريقة مختلفة. `--insecure` يسمح باكتشاف HTTPS ذات الشهادة الذاتية في اللاب.

## التحقق من السكربت

```bash
python3 -m unittest discover -s tests -v
```

الاختبارات تستخدم خادم HTTP محلي وبرامج scanners محاكية. تتحقق من تمرير النتائج
وترتيب الفحوص، منع shell injection، رفض URLs خارج IP الإدخال، عدم اتباع redirect
في discovery، dry-run، حدود التوازي، timeouts، وإنشاء التقارير. لا تثبت كفاءة scanners
ولا تغني عن تجربة نسخها الحقيقية في Kali. أدوات الفحص الحقيقية لم تكن متوفرة في
بيئة إنشاء هذا المشروع؛ الأوامر راجعت مراجعها الرسمية وKali.

## المراجع

- [Nmap XML output](https://nmap.org/book/man-output.html)
- [ProjectDiscovery HTTPx](https://github.com/projectdiscovery/httpx)
- [WhatWeb](https://github.com/urbanadventurer/WhatWeb)
- [FFUF](https://github.com/ffuf/ffuf)
- [Gobuster](https://github.com/OJ/gobuster)
- [Feroxbuster CLI on Kali](https://www.kali.org/tools/feroxbuster/)
- [Dirsearch CLI on Kali](https://www.kali.org/tools/dirsearch/)
- [Nikto CLI on Kali](https://www.kali.org/tools/nikto/)
- [Nuclei flags](https://github.com/projectdiscovery/nuclei)
- [SQLmap usage](https://github.com/sqlmapproject/sqlmap/wiki/Usage)
