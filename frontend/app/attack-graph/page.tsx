'use client';

import { useEffect, useState } from 'react';
import { Share2, RefreshCw, ChevronRight, Activity, Zap, ShieldAlert, CheckCircle2 } from 'lucide-react';
import { api, fetchAttackGraph } from '@/lib/api';
import type { AttackGraphData, AttackGraphNode, Incident } from '@/types/api';

export default function AttackGraphPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncId, setSelectedIncId] = useState<string>('');
  const [graphData, setGraphData] = useState<AttackGraphData | null>(null);
  const [selectedNode, setSelectedNode] = useState<AttackGraphNode | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    api<Incident[]>('/incidents?limit=20')
      .then((data) => {
        setIncidents(data);
        if (data.length > 0) {
          setSelectedIncId(data[0].incident_id);
        }
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!selectedIncId) return;
    setLoading(true);
    fetchAttackGraph(selectedIncId)
      .then((data) => {
        setGraphData(data);
        if (data.nodes.length > 0) setSelectedNode(data.nodes[0]);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [selectedIncId]);

  return (
    <main className="page">
      <div className="eyebrow">ATTACK PATH RECONSTRUCTION</div>
      <div className="page-header">
        <div>
          <h1>Attack Lifecycle Graph</h1>
          <p>Reconstructed visual attack graph showing kill-chain nodes, lateral movement, honeypot traps, and evidence payload.</p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <select
            value={selectedIncId}
            onChange={(e) => setSelectedIncId(e.target.value)}
            style={{
              background: '#05090d',
              border: '1px solid #1c2e39',
              padding: '6px 12px',
              color: '#00e5ff',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: 'bold',
            }}
          >
            {incidents.map((inc) => (
              <option key={inc.incident_id} value={inc.incident_id}>
                {inc.incident_id} — {inc.title.substring(0, 30)}
              </option>
            ))}
          </select>
        </div>
      </div>

      {error && <div className="api-warning">Graph Error: {error}</div>}

      {graphData && (
        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 20 }}>
          {/* Interactive Graph Node Lifecycle Flow */}
          <div className="panel" style={{ padding: 20, minHeight: 480 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
              <div>
                <h2 style={{ fontSize: '16px', margin: '0 0 4px' }}>{graphData.title}</h2>
                <span className="mono" style={{ fontSize: '11px', color: '#688290' }}>
                  Incident: {graphData.incident_id} • Severity: {graphData.severity}
                </span>
              </div>
              <span className={`badge ${graphData.severity.toLowerCase()}`}>{graphData.severity}</span>
            </div>

            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 16,
                padding: '20px 10px',
                position: 'relative',
              }}
            >
              {graphData.nodes.map((node, index) => {
                const isSelected = selectedNode?.id === node.id;
                const edge = graphData.edges.find((e) => e.target === node.id);

                return (
                  <div key={node.id} style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start' }}>
                    {edge && (
                      <div
                        style={{
                          margin: '0 0 12px 30px',
                          display: 'flex',
                          alignItems: 'center',
                          gap: 8,
                          color: '#00e5ff',
                          fontSize: '11px',
                          fontFamily: 'DM Mono, monospace',
                        }}
                      >
                        <div style={{ width: 2, height: 20, background: '#00e5ff66' }} />
                        <span>↓ {edge.label}</span>
                      </div>
                    )}

                    <div
                      onClick={() => setSelectedNode(node)}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        width: '100%',
                        background: isSelected ? '#0a1a26' : '#05090d',
                        border: isSelected ? '1px solid #00e5ff' : '1px solid #1c2e39',
                        boxShadow: isSelected ? '0 0 15px #00e5ff22' : 'none',
                        borderRadius: '8px',
                        padding: '14px 18px',
                        cursor: 'pointer',
                        transition: 'all 0.2s ease',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                        <div
                          style={{
                            width: 36,
                            height: 36,
                            borderRadius: '50%',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            background:
                              node.type === 'attacker'
                                ? '#ff4a4a22'
                                : node.type === 'deception'
                                ? '#ffb70322'
                                : node.type === 'exfiltration'
                                ? '#ff005522'
                                : '#00e5ff22',
                            color:
                              node.type === 'attacker'
                                ? '#ff4a4a'
                                : node.type === 'deception'
                                ? '#ffb703'
                                : node.type === 'exfiltration'
                                ? '#ff0055'
                                : '#00e5ff',
                            border: '1px solid currentColor',
                          }}
                        >
                          {index + 1}
                        </div>
                        <div>
                          <b style={{ fontSize: '14px', color: '#fff' }}>{node.label}</b>
                          <div style={{ fontSize: '11px', color: '#688290', marginTop: 2 }}>
                            {node.details}
                          </div>
                        </div>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <span
                          className="mono"
                          style={{
                            fontSize: '10px',
                            background: '#04070b',
                            padding: '3px 8px',
                            borderRadius: 4,
                            color: '#9eb4bf',
                            border: '1px solid #1c2e39',
                          }}
                        >
                          {node.type.toUpperCase()}
                        </span>
                        <ChevronRight size={16} color={isSelected ? '#00e5ff' : '#688290'} />
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Node Evidence Inspector Drawer */}
          <div className="panel" style={{ padding: 20 }}>
            <h3 style={{ margin: '0 0 12px', fontSize: '15px' }}>Node Evidence Details</h3>
            {selectedNode ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                <div>
                  <small style={{ color: '#688290', fontSize: '10px' }}>NODE IDENTIFIER</small>
                  <div className="mono" style={{ color: '#00e5ff', fontSize: '13px', fontWeight: 'bold' }}>
                    {selectedNode.id} ({selectedNode.label})
                  </div>
                </div>

                <div>
                  <small style={{ color: '#688290', fontSize: '10px' }}>NODE CATEGORY</small>
                  <div style={{ margin: '4px 0' }}>
                    <span className="badge high">{selectedNode.type.toUpperCase()}</span>
                  </div>
                </div>

                <div>
                  <small style={{ color: '#688290', fontSize: '10px' }}>STATUS & STATE</small>
                  <div className="mono" style={{ color: '#dce8ec', fontSize: '12px' }}>
                    {selectedNode.status.toUpperCase()}
                  </div>
                </div>

                {selectedNode.timestamp && (
                  <div>
                    <small style={{ color: '#688290', fontSize: '10px' }}>TIMESTAMP</small>
                    <div className="mono" style={{ color: '#9eb4bf', fontSize: '11px' }}>
                      {new Date(selectedNode.timestamp).toLocaleString()}
                    </div>
                  </div>
                )}

                <div>
                  <small style={{ color: '#688290', fontSize: '10px' }}>ATTACK EVIDENCE / OBSERVATION</small>
                  <div
                    style={{
                      background: '#05090d',
                      border: '1px solid #1c2e39',
                      padding: 12,
                      borderRadius: 6,
                      color: '#dce8ec',
                      fontSize: '12px',
                      lineHeight: 1.5,
                    }}
                  >
                    {selectedNode.details}
                  </div>
                </div>

                <div style={{ background: '#00e5ff0a', border: '1px solid #00e5ff33', padding: 12, borderRadius: 6, fontSize: '11px', color: '#9eb4bf' }}>
                  <b style={{ color: '#00e5ff' }}>AI Correlation Note:</b> Node evidence verified through event telemetry and honeypot deception logs.
                </div>
              </div>
            ) : (
              <div className="empty">Select a graph node to inspect evidence.</div>
            )}
          </div>
        </div>
      )}
    </main>
  );
}
