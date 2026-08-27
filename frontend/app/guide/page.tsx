'use client';

import { BookOpen, Brain, Database, FileText, Play, ScrollText, Shield, Terminal } from 'lucide-react';

const modules = [
  ['Boshqaruv paneli', 'Tizimning umumiy xavfsizlik holati, risk ko‘rsatkichi, hodisalar va monitoring metrikalarini ko‘rsatadi.'],
  ['Xavfsizlik hodisalari', 'Backenddan kelayotgan security eventlarni ko‘rish, filtrlash va tekshirish uchun ishlatiladi.'],
  ['Hodisa markazi', 'Aniqlangan incidentlarni OPEN, INVESTIGATING, CONTAINED va RESOLVED holatlarida boshqarish uchun.'],
  ['Tizim loglari', 'Hozircha event telemetry log ko‘rinishida ishlaydi. Keyingi bosqichda Django logging va markaziy log storage ulanadi.'],
  ['Aniqlash qoidalari', 'Detection qoidalarini ko‘rish va backend orqali yangilash uchun.'],
  ['MITRE ATT&CK', 'Hodisalarga bog‘langan hujum texnikalarini va attack chainni tushunish uchun.'],
  ['Endpoint agentlar', 'Monitoring qilinayotgan endpointlar holatini ko‘rish uchun.'],
  ['Honeypot markazi', 'Honeypot sessiyalari va deception telemetryni ko‘rish uchun.'],
  ['Hujum simulyatori', 'Kiber poligonda demo scenario ishga tushirib, end-to-end incident hosil qilish uchun.'],
  ['Hujum yo‘li grafigi', 'Incident ichidagi hujum bosqichlarini grafik ko‘rinishda tekshirish uchun.'],
  ['AI xavfsizlik tahlili', 'Incident report ma’lumotlarini AI yordamida tahlil qilish interfeysi. AI provider API hali konfiguratsiya qilinmagan bo‘lsa, bu modul to‘liq ishlamaydi.'],
  ['Avtomatik hisobotlar', 'Investigation reportlarni ko‘rish va yakuniy hisobotga aylantirish uchun.'],
];

export default function GuidePage() {
  return <main className="page">
    <div className="eyebrow">SANITIALX / FOYDALANISH QO‘LLANMASI</div>
    <div className="page-header"><div><h1>Qo‘llanma va test rejasi</h1><p>Platformani qanday ishlatish, qaysi modul nima qilishi va demo ko‘rsatmani qanday bajarish.</p></div></div>

    <div className="guide-grid">
      <section className="guide-card"><BookOpen size={20} color="#35e0ff"/><h3>1. Boshlash</h3><p>Avval backend API va PostgreSQL ishga tushiriladi. Frontend <code>NEXT_PUBLIC_API_URL</code> orqali backendga ulanadi. Login orqali access token olinadi va keyingi API so‘rovlari Bearer token bilan yuboriladi.</p></section>
      <section className="guide-card"><Play size={20} color="#45e0a2"/><h3>2. Demo test</h3><p>Yuqoridagi <b>Demo hujumni ishga tushirish</b> tugmasini bosing. Frontend <code>/simulations/run</code> endpointiga scenario yuboradi. Backend incident yaratgach, Simulyatsiya sahifasiga o‘tiladi.</p></section>
      <section className="guide-card"><ScrollText size={20} color="#35e0ff"/><h3>3. Log va hodisalar</h3><p>Real telemetry avval backendga keladi. Hodisalar <code>/events</code>, incidentlar esa <code>/incidents</code> orqali olinadi. Hozirgi UI shu API'lar bilan ishlaydi; alohida markaziy log collector hali keyingi bosqich.</p></section>
      <section className="guide-card"><Brain size={20} color="#6d8cff"/><h3>4. AI</h3><p>AI sahifasi incident tanlaydi va investigation reportni <code>/reports/:incident_id</code> orqali oladi. AI provider/API key backendda konfiguratsiya qilingandan keyin real reasoning natijasi chiqadi.</p></section>
      <section className="guide-card"><Database size={20} color="#ffad5c"/><h3>5. Ma’lumotlar oqimi</h3><p>Frontend → Django API → PostgreSQL. Security event → incident → investigation report → AI analysis zanjiri platformaning asosiy workflowidir.</p></section>
      <section className="guide-card"><Terminal size={20} color="#45e0a2"/><h3>6. Ertangi demo ketma-ketligi</h3><ol><li>Login qiling.</li><li>Dashboardni ko‘rsating.</li><li>Demo hujumni ishga tushiring.</li><li>Yangi incidentni oching.</li><li>Event va MITRE texnikasini tekshiring.</li><li>Attack Graphni ko‘rsating.</li><li>AI Analysis va Report modulini tushuntiring.</li></ol></section>
    </div>

    <div className="guide-card" style={{marginTop:12}}><h3><Shield size={18} color="#35e0ff"/> Hozirgi tayyorlik holati</h3><p><b>UI:</b> asosiy modullar mavjud. <b>Backend integratsiya:</b> auth, events, incidents, agents, honeypots, simulations, attack graph va reports API'lari frontendda chaqirilmoqda. <b>AI:</b> frontend workflow mavjud, lekin provider API konfiguratsiyasi kerak. <b>Markaziy loglar:</b> alohida collector/storage qatlamini qo‘shish kerak.</p></div>
  </main>;
}
