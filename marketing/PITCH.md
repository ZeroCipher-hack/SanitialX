# SanitialX — himoya pitch'i va savol-javoblar

> Matnda faqat loyihada **haqiqatan bor** narsalar aytilgan. Bo'lmaganini ("hali yo'q") alohida belgilab qo'ydim, chunki komissiya aynan shu joydan savol beradi.

## 1. 30 soniyalik pitch (lift)

"Banklar va kompaniyalar kunlik minglab xavfsizlik hodisalari va zaifliklar ichida cho'kib ketadi. **SanitialX** — ularni bitta panelda ko'rsatadigan SOC platformasi: hujumni aniqlaydi, MITRE ATT&CK bilan bog'laydi, AI yordamida tushuntiradi va javob amalini **faqat odam tasdig'idan keyin** bajaradi. Eng muhimi — u mijozning **o'z serverida** ishlaydi va internetsiz ham ishlaydi, shuning uchun bank ma'lumotini hech kimga ishonib topshirmaydi."

## 2. Himoya tuzilishi (7–8 daqiqa)

| # | Bo'lim | Vaqt | Nima deyiladi |
|---|--------|------|----------------|
| 1 | Muammo | 1 min | Hodisalar va zaifliklar oqimi; kichik jamoalar real xavfni ajrata olmaydi. Mavjud deckdagi `40 000+ CVE / ~6% ekspluatatsiya` slaydini ishlating. |
| 2 | Yechim | 1 min | Aniqlaydi → tahlil qiladi → nazoratli javob beradi. Bitta platforma. |
| 3 | Jonli demo | 2.5 min | Quyidagi demo ssenariysi. |
| 4 | Nima bilan farq qiladi | 1 min | On-prem/offline, tasdiqli SOAR, CVE ustuvorligi (CVSS × EPSS × KEV). |
| 5 | Arxitektura | 1 min | Scapy sensor → normalizer → Redis Streams → korrelyatsiya → PostgreSQL → FastAPI → Next.js. |
| 6 | Biznes model | 1 min | Mijoz o'z serveriga o'rnatadi; reja va agent soniga qarab imzolangan litsenziya. |
| 7 | Yo'l xaritasi | 0.5 min | Quyida, "Hali yo'q" bo'limi. |

## 3. Jonli demo ssenariysi (2.5 min)

1. Login → **Boshqaruv paneli** (umumiy holat).
2. **Demo hujumni ishga tushirish** tugmasi → yangi hodisa paydo bo'ladi.
3. **Hodisa markazi** → hodisani oching, MITRE texnikasi va vaqt chizig'ini ko'rsating.
4. **Hujum yo'li grafigi** (bosqichlar zanjiri).
5. **SOAR**: javob amalini taklif qiling → *tasdiq so'raydi* (shu joyni alohida ta'kidlang: "avtomatik emas, nazoratli").
6. **Hisobot** → bosmaga tayyor SOC hisobotini oching.
7. Oxirida **Litsenziya** sahifasi: "mijozda internet bo'lmasa ham tekshiriladi".

Demo oldidan: backend, PostgreSQL va Redis ishlayotganini tekshiring, brauzerda tokenni oldindan oling. Internet ishlamay qolsa deyarli hamma narsa ishlayveradi (AI bundan mustasno).

## 4. Asosiy dalillar (nima bilan himoya qilasiz)

- **Ma'lumot mijozda qoladi.** Vendorga hech narsa avtomatik ketmaydi: yordam murojaatlari va yangiliklar qo'lda (eksport/import) almashinadi.
- **Imzolangan litsenziya.** Ed25519, internetsiz tekshiriladi; yangi agent limiti va muddati majburlanadi, ishlab turgan agentlar to'xtamaydi (himoya uzilmasligi uchun).
- **Nazoratli SOAR.** Har bir javob amali tasdiqdan o'tadi va audit qilinadi.
- **Aniqlash qoidalari:** port skanerlash, SSH / RDP / ma'lumotlar bazasi brute-force, SMB lateral movement, honeypot + hujum zanjiri (recon → brute-force) qoidasi.
- **Zaiflik ustuvorligi:** CVSS × EPSS × KEV (mavjud pitch deckdagi "Dormant-CVE" misoli juda kuchli dalil).
- **Sifat:** backendda 291 ta avtomatik test o'tadi.

## 5. Hali yo'q — oldindan tan oling

Komissiya buni o'zi topadi; siz birinchi aytsangiz ishonch oshadi.

- **AI tahlil Gemini (Google) orqali ishlaydi** — bu hodisa ma'lumotini tashqariga yuboradi. Shuning uchun u **sukut bo'yicha o'chiq** (kalit berilmasa ishlamaydi). Bank rejimida o'chiriladi; yo'l xaritasi: mahalliy (on-prem) model.
- Aniqlash qoidalari hozircha **ulanish chastotasiga** asoslangan: parol xatosini isbotlamaydi. Bu qoidalarning tavsifida ham shunday yozilgan. False positive bo'lishi mumkin; chegaralar sozlanadi.
- Yuklama (load) va katta tarmoqdagi samaradorlik **o'lchanmagan**. "Soniyada nechta hodisa" degan raqam aytmang.
- Vendor paneli (mijozlar soni, statistika, markaziy tiketlar) **hali qurilmagan**. Mijoz tomoni (Yordam, Yangiliklar, Litsenziya) tayyor.
- Haqiqiy bankda sinov (pilot) o'tkazilmagan. Pilot rejasi: 1 ta kichik tashkilot, 30 kun.
- Xavfsizlik auditi (tashqi pentest) o'tkazilmagan.

## 6. Ehtimoliy savollar va javoblar

**Wazuh, Splunk, Elastic bilan farqingiz nima?**
Ular kuchli, lekin murakkab va qimmat. Biz kichik va o'rta jamoalar uchun bitta tayyor, o'zbek tilidagi, tez o'rnatiladigan paket beramiz: aniqlash + tahlil + nazoratli javob + zaiflik ustuvorligi. Katta platformalar bilan raqobat emas, ularga qurbi yetmaydigan segment.

**Nega bank sizga ishonsin?**
Biz ma'lumotni ko'rmaymiz: tizim ularning serverida, vendorga avtomatik hech narsa ketmaydi. Ishonch so'ralmaydi, arxitektura o'zi kafolat beradi. Kod va litsenziya mexanizmi tekshiriladigan.

**Litsenziyani buzib bo'ladimi?**
Yo'l qo'yilmaydi: fayl imzolangan, o'zgartirilsa imzo buziladi. Ochiq kalitni almashtirish mumkin, bu shartnoma va yuridik himoya bilan qoplanadi; to'liq texnik himoya (obfuskatsiya) mavjud emas va men buni yashirmayman.

**AI ma'lumotni tashqariga chiqarmaydimi?**
Ha, Gemini ishlatilsa chiqaradi. Shuning uchun sukut bo'yicha o'chiq va mijoz yoqadi. Bank uchun mahalliy modelga o'tish rejada.

**False positive'lar-chi?**
Qoidalar chegaralari (urinishlar soni, oyna, cooldown) sozlanadi va hodisalar tasdiqsiz javob bermaydi, shuning uchun noto'g'ri signal zarar keltirmaydi.

**Masshtab qanchaga yetadi?**
Redis Streams va PostgreSQL asosida, lekin yuklama sinovi hali o'tkazilmagan; birinchi pilotda o'lchaymiz.

**Daromad modeli?**
Yillik imzolangan litsenziya (agent soni va reja bo'yicha) + o'rnatish va qo'llab-quvvatlash xizmati.

**Jamoa va keyingi qadam?**
Pilot → tashqi xavfsizlik auditi → vendor paneli → mahalliy AI modeli.

## 7. Instagram: reklama va targeting

**Video:** `marketing/promo-reel/out/sanitialx-reel.mp4` (1080×1920, 27 soniya).

**Sarlavha (caption):**
> Hujum boshlandi. Siz buni qachon bilasiz? 🛡️
> SanitialX hujumni real vaqtda ko'radi, tahlil qiladi va javobni faqat sizning tasdig'ingiz bilan bajaradi. Ma'lumotlaringiz o'z serveringizda qoladi, internetsiz ham ishlaydi.
> Demo uchun DM yozing 👇

**Hashtaglar:** #kiberxavfsizlik #cybersecurity #SOC #SIEM #bank #infosec #ozbekiston #IT

**Targeting (Meta Ads Manager):**
- Joylashuv: O'zbekiston (Toshkent birinchi).
- Yosh: 25–50.
- Qiziqishlar/lavozimlar: axborot xavfsizligi, IT boshqaruv, bank texnologiyalari, tizim administratori, CIO/CISO.
- Maqsad: **Messages (DM)** yoki Lead; tugma "Send message".
- Byudjet: kuniga 5–10 USD bilan 7 kun sinab, qaysi auditoriya DM berayotganini ko'ring; keyin kengaytiring.
- Bank va davlat tashkilotlariga Instagram'dan ko'ra **LinkedIn va Telegram** ko'proq ishlaydi: ularga to'g'ridan-to'g'ri yozing va demo taklif qiling.

**Eslatma:** reklamada "100% himoya", "hech qachon buzilmaydi" kabi kafolat va'dalari bermang. Ular yolg'on bo'lib chiqadi va reklama siyosatini ham buzadi.
