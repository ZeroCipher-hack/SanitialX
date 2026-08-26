'use client';

import { useState } from 'react';
import { Layers, Search, ExternalLink } from 'lucide-react';

const MITRE_TACTICS = [
  {
    tactic: 'Reconnaissance',
    id: 'TA0043',
    techniques: [
      { id: 'T1046', name: 'Network Service Scanning', desc: 'Scanning ports to discover active services (e.g. nmap).' },
    ],
  },
  {
    tactic: 'Initial Access',
    id: 'TA0001',
    techniques: [
      { id: 'T1110.001', name: 'Password Guessing', desc: 'Brute force credential spray against web/SSH login endpoints.' },
      { id: 'T1190', name: 'Exploit Public-Facing Application', desc: 'Exploiting web app vulnerabilities for unauthorized entry.' },
    ],
  },
  {
    tactic: 'Execution',
    id: 'TA0002',
    techniques: [
      { id: 'T1059.004', name: 'Unix Shell', desc: 'Executing arbitrary commands via interactive shell or web shell.' },
    ],
  },
  {
    tactic: 'Persistence & Priv Esc',
    id: 'TA0004',
    techniques: [
      { id: 'T1548.001', name: 'Setuid and Setgid', desc: 'Exploiting misconfigured SUID binaries to elevate privileges to root.' },
      { id: 'T1078', name: 'Valid Accounts', desc: 'Reusing compromised SSH keys or backup admin credentials.' },
    ],
  },
  {
    tactic: 'Discovery & Deception',
    id: 'TA0007',
    techniques: [
      { id: 'T1087', name: 'Account Discovery', desc: 'Searching system users; trapped by Honeypot Deception node.' },
      { id: 'T1005', name: 'Data from Local System', desc: 'Reading database records and customer database dumps.' },
    ],
  },
  {
    tactic: 'Exfiltration',
    id: 'TA0010',
    techniques: [
      { id: 'T1041', name: 'Exfiltration Over C2 Channel', desc: 'Transferring stolen sensitive data outbound to malicious C2 IP.' },
    ],
  },
];

export default function TechniquesPage() {
  const [q, setQ] = useState('');

  return (
    <main className="page">
      <div className="eyebrow">DETECTION KNOWLEDGE</div>
      <div className="page-header">
        <div>
          <h1>MITRE ATT&CK Matrix Explorer</h1>
          <p>Mapped attacker techniques, tactics, and procedures (TTPs) supported by SanitialX detection rules and cyber range simulations.</p>
        </div>
      </div>

      <div className="toolbar" style={{ marginBottom: 20 }}>
        <div className="search" style={{ width: '100%' }}>
          <Search size={15} />
          <input
            placeholder="Search MITRE technique ID or technique name..."
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 16 }}>
        {MITRE_TACTICS.map((tac) => (
          <div key={tac.id} className="panel" style={{ padding: 18 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <span className="mono" style={{ fontSize: '11px', color: '#00e5ff' }}>
                {tac.id}
              </span>
              <span style={{ fontSize: '10px', color: '#688290' }}>{tac.techniques.length} TECHNIQUES</span>
            </div>

            <h3 style={{ margin: '0 0 14px', fontSize: '15px', color: '#fff' }}>{tac.tactic}</h3>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {tac.techniques
                .filter(
                  (tech) =>
                    tech.id.toLowerCase().includes(q.toLowerCase()) ||
                    tech.name.toLowerCase().includes(q.toLowerCase()) ||
                    tech.desc.toLowerCase().includes(q.toLowerCase())
                )
                .map((tech) => (
                  <div
                    key={tech.id}
                    style={{
                      background: '#05090d',
                      border: '1px solid #1c2e39',
                      padding: 12,
                      borderRadius: 6,
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                      <span className="mono" style={{ fontSize: '12px', fontWeight: 'bold', color: '#00e5ff' }}>
                        {tech.id}
                      </span>
                      <small style={{ color: '#688290', fontSize: '10px' }}>MITRE ATT&CK</small>
                    </div>
                    <b style={{ fontSize: '13px', color: '#fff', display: 'block', marginBottom: 4 }}>
                      {tech.name}
                    </b>
                    <p style={{ margin: 0, fontSize: '11px', color: '#9eb4bf', lineHeight: 1.4 }}>
                      {tech.desc}
                    </p>
                  </div>
                ))}
            </div>
          </div>
        ))}
      </div>
    </main>
  );
}
