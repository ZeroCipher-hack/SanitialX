# SanitialX ni VPS (Linux) ga o'rnatish

Bu yo'riqnoma GoDaddy VPS uchun yozilgan, lekin boshqa har qanday Ubuntu serverda ham xuddi shunday ishlaydi.
Serverga kirish ma'lumotlarini (parol, SSH kalit) faqat **siz** ishlatasiz; hech kimga yubormang.

Nima o'rnatiladi: PostgreSQL, Redis, backend (API), worker, zaiflik skeduleri, veb-panel va **Caddy** (avtomatik HTTPS).
Tashqariga faqat **80 va 443** portlar ochiladi; baza, Redis va API ichki tarmoqda qoladi.

---

## 0. Nimalar kerak

| Narsa | Tavsiya |
|-------|---------|
| Server | VPS, **Ubuntu 22.04 yoki 24.04**, kamida **2 vCPU, 4 GB RAM, 40 GB disk** |
| Domen | Ixtiyoriy, lekin HTTPS uchun tavsiya etiladi (masalan `soc.sizning-domen.uz`) |
| Sizning kompyuteringiz | Terminal (Linux/Mac) yoki PowerShell (Windows), `ssh` buyrug'i |

GoDaddy'da: **VPS Hosting** tanlang (oddiy "Web Hosting" yaramaydi), operatsion tizim **Ubuntu**, **root/SSH** kirish yoqilgan bo'lsin. Xarid qilgach GoDaddy sizga serverning **IP manzili** va kirish ma'lumotini beradi.

## 1. Domenni serverga yo'naltirish (ixtiyoriy, 5–30 daqiqa)

GoDaddy → Domenlar → DNS → **A yozuvi** qo'shing:
- Name: `soc` (yoki `@`), Value: **server IP manzili**, TTL: 600.

Tekshirish (o'z kompyuteringizda): `ping soc.sizning-domen.uz` serverning IP'sini ko'rsatishi kerak.

## 2. Serverga kirish va tayyorlash

```bash
ssh root@SERVER_IP
```

Tizimni yangilash va xavfsizlik devori:

```bash
apt update && apt upgrade -y
apt install -y ufw git curl openssl
ufw allow OpenSSH && ufw allow 80 && ufw allow 443 && ufw --force enable
```

Docker o'rnatish:

```bash
curl -fsSL https://get.docker.com | sh
docker --version && docker compose version
```

> Tavsiya: root o'rniga alohida foydalanuvchi bilan ishlang va SSH'ni kalit bilan kirishga o'tkazib, parol bilan kirishni o'chiring.

## 3. Loyihani serverga olish

**Variant A: GitHub'dan** (avval PR'ni `main`ga qo'shing, repo maxfiy bo'lsa GitHub token kerak):

```bash
git clone https://github.com/ZeroCipher-hack/SanitialX.git /opt/sanitialx
```

**Variant B: o'z kompyuteringizdan** (GitHub'siz, eng sodda). Kompyuteringizda, loyiha papkasida:

```bash
rsync -av --exclude node_modules --exclude .next --exclude .venv --exclude .git \
  ./ root@SERVER_IP:/opt/sanitialx/
```

## 4. Sozlash (sirlar avtomatik yaratiladi)

```bash
cd /opt/sanitialx/deploy
./setup.sh
```

Skript domen nomini so'raydi (domen bo'lmasa Enter bosing, IP orqali HTTP bilan ishlaydi) va tasodifiy parol/kalitlarni `deploy/.env` fayliga yozadi.
**`.env` faylini zaxiralab saqlang**; uni yo'qotsangiz, ma'lumotlar bazasiga kira olmaysiz.

## 5. Ishga tushirish

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

Birinchi qurish 5–15 daqiqa olishi mumkin. Holatni ko'rish:

```bash
docker compose -f docker-compose.prod.yml ps
docker compose -f docker-compose.prod.yml logs -f backend
```

Hamma servis `running`/`healthy` bo'lishi kerak (`migrate` tugagach `exited 0` bo'ladi, bu normal).

## 6. Birinchi administratorni yaratish

Tizimda ommaviy ro'yxatdan o'tish yo'q (xavfsizlik uchun). Admin terminal orqali yaratiladi:

```bash
docker compose -f docker-compose.prod.yml exec backend python -m scripts.create_user --username admin --role admin
```

Parolni ikki marta kiritasiz (kamida 8 belgi; ekranda ko'rinmaydi).

Endi brauzerda oching: `https://soc.sizning-domen.uz` (yoki `http://SERVER_IP`) → **Kirish**.

## 7. Tekshirish ro'yxati

- [ ] Sayt ochiladi, "Kirish" sahifasi chiqadi
- [ ] Admin bilan kirish ishlaydi, boshqaruv paneli ochiladi
- [ ] **Aniqlash qoidalari** sahifasida 6 ta qoida ko'rinadi
- [ ] **Hujum simulyatori** → "Demo hujum" hodisa yaratadi
- [ ] `https://.../api/v1/health` → `{"status":"ok"...}`
- [ ] Brauzerda qulf belgisi (HTTPS) bor

## 8. Kundalik ishlar

**Zaxira nusxa** (kuniga bir marta cron bilan):

```bash
/opt/sanitialx/deploy/backup.sh
# cron: 0 3 * * * /opt/sanitialx/deploy/backup.sh >> /var/log/sanitialx-backup.log 2>&1
```

**Yangilash** (yangi versiya chiqqanda):

```bash
cd /opt/sanitialx && git pull        # yoki rsync bilan yangi fayllarni yuklang
cd deploy && docker compose -f docker-compose.prod.yml up -d --build
```

**Qayta ishga tushirish / to'xtatish:**

```bash
docker compose -f docker-compose.prod.yml restart
docker compose -f docker-compose.prod.yml down        # ma'lumotlar saqlanadi (volume)
```

> `down -v` buyrug'ini **ishlatmang**: u ma'lumotlar bazasini o'chirib yuboradi.

## 9. Endpoint agentlarni ulash

Agent serverga `https://soc.sizning-domen.uz/api/v1/agents/enroll` manziliga murojaat qiladi va `X-Enrollment-Key` sifatida `deploy/.env` dagi `SENTINELX_API_KEY` qiymatini ishlatadi. Bu kalitni faqat ishonchli mashinalarga bering.

## 10. Litsenziya (sotishda)

1. O'zingizda: `python backend/scripts/license_tool.py keygen --out keys/` (maxfiy kalitni **hech qachon** mijozga bermang).
2. `license_public.key` mazmunini mijozning `deploy/.env` dagi `SENTINELX_LICENSE_PUBLIC_KEY=` ga yozing va `docker compose ... up -d` qiling.
3. Mijoz uchun `license_tool.py sign ...` bilan `license.json` yarating; admin uni panelda **Litsenziya** sahifasidan yuklaydi.

Ochiq kalit berilmasa, litsenziya cheklovi **ishlamaydi** (yangi agentlar cheklanmaydi). Sotishda uni albatta sozlang.

## 11. Muammolar bo'lsa

| Belgi | Sabab va yechim |
|-------|-----------------|
| Sayt ochilmaydi | `docker compose ... ps` va `logs caddy`. Domen DNS'i hali yangilanmagan bo'lishi mumkin. |
| HTTPS sertifikat olinmaydi | 80 va 443 portlar ochiqmi (`ufw status`), A yozuvi to'g'ri IP'gami. |
| "Failed to fetch" paneli | `PUBLIC_URL` noto'g'ri; `.env` ni tuzatib, `up -d --build` (frontend qayta quriladi). |
| Backend ishga tushmaydi | `logs backend`: odatda `.env` dagi kalit kamida 32 belgi bo'lishi kerak (`setup.sh` shuni qiladi). |
| Disk to'ldi | `docker system prune -f` (ishlatilmagan imijlarni tozalaydi; volume'larga tegmaydi). |

## 12. Hozircha ma'lum cheklovlar (halol ro'yxat)

- Production Docker qurilishi **men tomondan serverda sinalmagan**: frontend production build va konfiguratsiya tekshirilgan, lekin birinchi `up --build` ni haqiqiy VPS'da kuzatish kerak.
- Panelda foydalanuvchilarni boshqarish sahifasi hali yo'q: yangi foydalanuvchi faqat yuqoridagi `create_user` buyrug'i bilan yaratiladi.
- AI tahlil sukut bo'yicha o'chiq (`SENTINELX_GEMINI_API_KEY` bo'sh). Yoqilsa, hodisa matni Google'ga yuboriladi.
- Agentlar ulanishida tarmoq sniffer (Scapy) konteyner ichida cheklangan huquq bilan ishlamaydi; hodisalar asosan agentlar orqali keladi.
