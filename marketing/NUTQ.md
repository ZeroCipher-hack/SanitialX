# SanitialX — himoya nutqi (slayd bo'yicha)

Taqdimot: `marketing/deck/index.html` (brauzerda oching, **F** — to'liq ekran, **← →** — slaydlar). PDF: `marketing/deck/out/SanitialX-taqdimot.pdf`.
Umumiy vaqt: **8–9 daqiqa** + savol-javob. Qalin yozilgan jumlalarni so'zma-so'z ayting, qolganini o'z so'zingiz bilan.

**Asosiy qoida:** nima **bor** bo'lsa shuni ayting, nima **yo'q** bo'lsa buni o'zingiz oldin tan oling. Komissiya "hozir nima ishlaydi?" deb so'raganda aniq javob bera olish — eng kuchli himoya.

---

## 1 · Sarlavha (20 soniya)
**"Assalomu alaykum. Men Tolqin Akramov. Bugun sizga SanitialX ni taqdim etaman: bank va tashkilotlar uchun xavfsizlik operatsiyalari markazi, ya'ni SOC platformasi."**

- Bir jumlada: hujumni aniqlaydi, javobni faqat odam tasdig'idan keyin bajaradi, o'z serveringizda ishlaydi.

## 2 · Muammo (40 soniya)
**"Xavfsizlik jamoalari signal ichida cho'kib ketadi."**

- Tarmoq va endpointlardan hodisalar tinimsiz keladi. Qaysi biri haqiqiy hujum, qaysi biri shovqin?
- Yiliga taxminan 40 000 ta yangi zaiflik (CVE) e'lon qilinadi, hammasini tuzatib bo'lmaydi.
- Ko'p tashkilotda xavfsizlik bo'limi bir-uch kishi. Splunk kabi katta tizimlarga resurs ham, mutaxassis ham yo'q.
- *Eslatma:* 40 000 raqami taxminiy (NVD statistikasi). "Taxminan" deb ayting.

## 3 · Yechim (40 soniya)
**"SanitialX uch ish qiladi: aniqlaydi, tahlil qiladi va nazoratli javob beradi."**

- **Aniqlaydi:** qoidalar va hujum zanjiri bilan.
- **Tahlil qiladi:** MITRE ATT&CK bilan bog'laydi; AI tahlil ixtiyoriy.
- **Javob beradi:** faqat odam tasdig'idan keyin.

## 4 · Jonli mahsulot (50 soniya) — shu yerda **demo** qilish mumkin
**"Mana haqiqiy mahsulot. Bitta boshqaruv panelida hamma narsa bor."**

- Xavfsizlik holati va risk indeksi, faol hodisalar, endpoint agentlar, tahdid manbalari xaritasi, so'nggi hodisalar.
- Agar jonli demo qilsangiz: login → "Demo hujumni ishga tushirish" → yangi hodisa paydo bo'lishini ko'rsating.
- *Eslatma:* ekranlardagi ma'lumot kiber poligon (simulyatsiya) natijasi, haqiqiy mijoz ma'lumoti emas. Buni ochiq ayting.

## 5 · Aniqlash (50 soniya)
**"Hozir oltita qoida va bitta hujum zanjiri bor."**

- Port skanerlash, SSH brute-force, RDP brute-force, SMB lateral movement, ma'lumotlar bazasi brute-force, honeypot.
- Har biri MITRE ATT&CK texnikasiga bog'langan.
- **Hujum zanjiri:** razvedka va undan keyin brute-force bitta yuqori ustuvor hodisaga aylanadi.
- **Halol cheklov (oldindan ayting):** bu qoidalar ulanish **chastotasiga** asoslangan. Ular parol xatosini isbotlamaydi. Chegaralar (urinishlar soni, vaqt oynasi) sozlanadi.

## 6 · Hujum yo'li (40 soniya)
**"Hujum bosqichma-bosqich ko'rinadi."**

- Grafikda: manba → asosiy nishon → ma'lumotlar bazasi → tashqariga chiqish (exfiltration), texnikalar T1548, T1005, T1041.
- Har bir tugun uchun dalil ko'rsatiladi.

## 7 · Nazoratli javob (SOAR) (50 soniya)
**"Hech narsa nazoratsiz bajarilmaydi."**

- To'rt qadam: taklif → tasdiq → bajarish → audit.
- **Nega muhim:** noto'g'ri signal endpointga zarar keltirmaydi, chunki odam tasdig'isiz amal qo'llanmaydi. Banklar uchun bu juda muhim.

## 8 · Zaiflik ustuvorligi (50 soniya)
**"4000 ta zaiflik emas, bugun muhim bo'lgan bir nechtasini ko'rsatamiz."**

- CVSS (qanchalik jiddiy) × EPSS (ekspluatatsiya ehtimoli) × KEV (tabiatda ishlatilyaptimi) = Risk.
- Misol: CVSS 9.8 "kritik" zaiflik, lekin KEV emas va EPSS 2%. U CVSS 7.5 bo'lgan, ammo tabiatda ishlatilayotgan zaiflikdan pastda turadi.
- *Eslatma:* "12 tasi" illustrativ misol. Ma'lumot manbalari (NVD, CISA KEV) internet orqali yangilanadi; offline muhitda yangilash qo'lda.

## 9 · Arxitektura (50 soniya)
**"Asinxron va modulli konveyer."**

- Sensor/agent → normalizer → Redis Streams → korrelyatsiya → PostgreSQL → FastAPI → Next.js panel.
- JWT va rollar (admin, analitik) bilan himoyalangan API.
- **Sifat:** 291 ta avtomatik backend testi o'tadi.
- Texnik savol bersa: har bosqich alohida modul, qoida qo'shish uchun bitta kichik klass yoziladi (masalan, RDP qoidasi atigi bir necha qator).

## 10 · Banklar uchun: ishonch (60 soniya) — **eng muhim slayd**
**"Ma'lumotlaringiz o'z serveringizda qoladi."**

- Mijoz tizimni o'z infratuzilmasiga o'rnatadi. Vendorga (menga) avtomatik hech narsa yuborilmaydi.
- Litsenziya imzolangan fayl (Ed25519), internetsiz tekshiriladi. Yangi agent limiti va muddati majburlanadi; allaqachon ishlayotgan agentlar to'xtamaydi, shunda himoya uzilmaydi.
- Yangiliklar va yordam javoblari qo'lda almashinadi, shuning uchun internetsiz bank tarmog'ida ham ishlaydi.
- **Sababi:** banklar xavfsizlik ma'lumotini tashqi bulutga topshirmaydi, bu normal va qonun talablariga ham mos.

## 11 · Biznes model (40 soniya)
**"Yillik litsenziya va qo'llab-quvvatlash."**

- Litsenziya agent soni va rejaga qarab. O'rnatish va yordam xizmati alohida.
- Mijoz panelida Yordam markazi, Yangiliklar va Litsenziya sahifalari tayyor.
- *Narxlar:* aniq raqam aytmang. "Pilot natijasiga qarab belgilanadi" deng.

## 12 · Holat va yo'l xaritasi (60 soniya) — **ishonch quriladigan joy**
Uch ustunni ketma-ket o'qing.

**Hozir bor:** 6 ta qoida va zanjir; hodisalar, grafik, hisobotlar; tasdiqli SOAR va endpoint agentlar; zaiflik ustuvorligi; offline litsenziya, yordam va yangiliklar.

**Keyingi bosqich:** vendor paneli (mijozlar soni, statistika); mahalliy AI model; 1 ta tashkilotda 30 kunlik pilot; tashqi xavfsizlik auditi; yuklama sinovi.

**Halol cheklovlar:**
- AI tahlil hozir Gemini (Google) orqali ishlaydi va ma'lumotni tashqariga chiqaradi. Shuning uchun u sukut bo'yicha **o'chiq**; bank rejimida o'chiq turadi. Mahalliy model rejada.
- Qoidalar chastotaga asoslangan.
- Katta yuklamada hali o'lchanmagan.
- Haqiqiy bankda hali sinalmagan.

**"Men buni yashirmayman. Aynan shuning uchun keyingi qadam pilot."**

## 13 · Video (30 soniya)
**"Endi qisqa video."** Videoni ishga tushiring (slaydga o'tganda o'zi boshlanadi; ovoz yo'q, shuning uchun tushuntirishingiz mumkin).

## 14 · Rahmat (10 soniya)
**"E'tiboringiz uchun rahmat. Savollaringiz bormi?"**

---

# Savol-javoblar (qisqa javoblar)

**Wazuh, Splunk, Elastic bilan farqingiz nima?**
Ular kuchli, lekin murakkab va qimmat, sozlash uchun mutaxassis kerak. Biz kichik va o'rta jamoalar uchun tayyor paketni beramiz: aniqlash + tahlil + nazoratli javob + zaiflik ustuvorligi, o'zbek tilida va tez o'rnatiladigan. Katta platformalar bilan raqobat qilmaymiz, ularga qurbi yetmaydigan segmentga xizmat qilamiz.

**Nega bank sizga ishonsin?**
Ishonch so'ralmaydi: tizim ularning serverida, vendorga hech narsa avtomatik ketmaydi. Ma'lumotni biz ko'rmaymiz.

**Litsenziyani buzib bo'ladimi?**
Faylni o'zgartirib bo'lmaydi: imzo buziladi. Lekin to'liq texnik himoya (kodni obfuskatsiya qilish) yo'q; asosiy himoya shartnoma va yuridik tomonlama. Buni yashirmayman.

**AI ma'lumotni tashqariga chiqarmaydimi?**
Ha, Gemini yoqilsa chiqaradi. Shuning uchun u sukut bo'yicha o'chiq va faqat mijoz yoqsa ishlaydi. Bank uchun mahalliy modelga o'tish rejada.

**False positive (noto'g'ri signal) bo'lsa-chi?**
Chegaralar sozlanadi va javob amali tasdiqsiz bajarilmaydi, shuning uchun noto'g'ri signal zarar keltirmaydi. Pilotda chegaralarni real trafikka moslaymiz.

**Qancha hodisani ko'taradi?**
Yuklama sinovi hali o'tkazilmagan, shuning uchun raqam aytmayman. Pilotda o'lchayman.

**Xavfsizlik auditidan o'tganmi?**
Hali yo'q. Tashqi audit keyingi bosqichda. Hozir 291 ta avtomatik test, parollar hash'langan, JWT va rollar, tizimga kirishda urinishlar cheklanadi.

**Nega boshqa tizimlar bo'lmagan "tasdiqli SOAR"?**
Boshqalarda ham bor, lekin biz uni birlamchi qoida qildik: tasdiqsiz hech narsa bajarilmaydi. Banklar avtomatik bloklashdan qo'rqadi, chunki xato bloklash xizmatni to'xtatadi.

**Daromad modeli?**
Yillik litsenziya (agent soni va reja bo'yicha) + o'rnatish va qo'llab-quvvatlash.

**Jamoa va keyingi qadamlar?**
Men asoschi va dasturchiman. Keyingi qadamlar: pilot, tashqi audit, vendor paneli, mahalliy AI.

**Nega "SanitialX"?**
Sanitary (tozalash) + X (noma'lum/tahdid): tarmoqni tahdidlardan "tozalaydi". *(O'zingiz ma'nosini o'z so'zingiz bilan tushuntirasiz.)*

---

# Nima aytmaslik kerak
- "Soniyada N ta hodisa", "100% himoya", "hech qachon buzilmaydi": o'lchanmagan va'dalar.
- "Bankda ishlaydi": hali haqiqiy pilot yo'q.
- "AI hamma narsani hal qiladi": AI ixtiyoriy yordamchi, javob baribir odam qo'lida.
- Demo ekranlardagi ma'lumotni "haqiqiy mijoz" deb atamang, bu kiber poligon.

# Demo oldidan tekshirish ro'yxati
1. Backend, PostgreSQL va Redis ishlayaptimi? Login ishlayaptimi?
2. Yangi demo hodisa hosil bo'lishini oldindan bir marta sinab ko'ring.
3. Internet yo'q bo'lishi mumkinligini hisobga oling: slayd va video fayllari lokal, internetsiz ishlaydi.
4. Zaxira: brauzerda ochilmasa, PDF nusxasi va videoni telefonda tayyor tuting.
