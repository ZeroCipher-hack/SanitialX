'use client';

import { Box, Server, Database, Shield, Zap } from 'lucide-react';

const ASSETS = [
  {
    name: 'web-prod-frontend-01',
    type: 'Web Application Server',
    ip: '10.0.0.50',
    role: 'Production Frontend (Next.js / Node API)',
    criticality: 'CRITICAL',
    status: 'COMPROMISED (Simulated)',
  },
  {
    name: 'db-internal-cluster-01',
    type: 'Database Server',
    ip: '10.0.0.88',
    role: 'Internal Customer DB (PostgreSQL)',
    criticality: 'CRITICAL',
    status: 'SENSITIVE READ DETECTED',
  },
  {
    name: 'decoy-ssh-vault',
    type: 'Honeypot Deception Node',
    ip: '10.0.0.99',
    role: 'SSH Vault & Fake Credentials Seed',
    criticality: 'LOW (Deception)',
    status: 'ACTIVE TRAP',
  },
  {
    name: 'firewall-perimeter-01',
    type: 'Perimeter Security Gateway',
    ip: '10.0.0.1',
    role: 'Border Router & WAF Gateway',
    criticality: 'HIGH',
    status: 'ONLINE',
  },
];

export default function AssetsPage() {
  return (
    <main className="page">
      <div className="eyebrow">ENVIRONMENT</div>
      <div className="page-header">
        <div>
          <h1>Cyber Range Assets</h1>
          <p>Inventory of registered network nodes, servers, databases, and deception targets in the lab environment.</p>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16 }}>
        {ASSETS.map((asset) => (
          <div key={asset.name} className="panel" style={{ padding: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <span className="mono" style={{ fontSize: '11px', color: '#00e5ff' }}>
                {asset.ip}
              </span>
              <span className={`badge ${asset.criticality.toLowerCase()}`}>{asset.criticality}</span>
            </div>

            <h3 style={{ margin: '0 0 4px', fontSize: '16px', color: '#fff' }}>{asset.name}</h3>
            <p style={{ margin: '0 0 12px', fontSize: '12px', color: '#688290' }}>{asset.type}</p>

            <div style={{ background: '#05090d', border: '1px solid #1c2e39', padding: 12, borderRadius: 6, fontSize: '12px', color: '#9eb4bf', lineHeight: 1.4 }}>
              <div><b>Role:</b> {asset.role}</div>
              <div style={{ marginTop: 4 }}><b>State:</b> <span style={{ color: '#ffb703' }}>{asset.status}</span></div>
            </div>
          </div>
        ))}
      </div>
    </main>
  );
}
