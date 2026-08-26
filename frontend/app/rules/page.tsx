'use client';

import { useEffect, useState } from 'react';
import { RefreshCw, Search, Edit2, CheckCircle, XCircle, X, AlertCircle, Loader2 } from 'lucide-react';
import { api, updateRule } from '@/lib/api';
import type { DetectionRule } from '@/types/api';

const SEVERITY_OPTIONS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export default function Rules() {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [q, setQ] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  // Edit modal state
  const [editingRule, setEditingRule] = useState<DetectionRule | null>(null);
  const [editName, setEditName] = useState('');
  const [editSeverity, setEditSeverity] = useState('HIGH');
  const [editDescription, setEditDescription] = useState('');
  const [editEnabled, setEditEnabled] = useState(true);
  const [editParamsJson, setEditParamsJson] = useState('{}');
  
  const [saving, setSaving] = useState(false);
  const [modalError, setModalError] = useState('');
  const [rowUpdatingId, setRowUpdatingId] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    setError('');
    api<DetectionRule[]>('/rules?limit=100')
      .then(setRules)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(load, []);

  const handleToggleEnabled = async (rule: DetectionRule) => {
    setRowUpdatingId(rule.rule_id);
    setError('');
    try {
      const updated = await updateRule(rule.rule_id, { enabled: !rule.enabled });
      setRules((prev) =>
        prev.map((r) => (r.rule_id === updated.rule_id ? updated : r))
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to update rule status.';
      setError(`[${rule.rule_id}] ${msg}`);
    } finally {
      setRowUpdatingId(null);
    }
  };

  const openEditModal = (rule: DetectionRule) => {
    setEditingRule(rule);
    setEditName(rule.rule_name);
    setEditSeverity(rule.severity || 'HIGH');
    setEditDescription(rule.description || '');
    setEditEnabled(rule.enabled);
    setEditParamsJson(JSON.stringify(rule.parameters || {}, null, 2));
    setModalError('');
  };

  const handleSaveRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingRule) return;

    setModalError('');
    let parsedParams: Record<string, unknown> = {};
    try {
      parsedParams = JSON.parse(editParamsJson);
    } catch {
      setModalError('Invalid JSON format for parameters.');
      return;
    }

    setSaving(true);
    try {
      const updated = await updateRule(editingRule.rule_id, {
        rule_name: editName,
        severity: editSeverity,
        description: editDescription,
        enabled: editEnabled,
        parameters: parsedParams,
      });

      setRules((prev) =>
        prev.map((r) => (r.rule_id === updated.rule_id ? updated : r))
      );
      setEditingRule(null);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to save rule updates.';
      setModalError(msg);
    } finally {
      setSaving(false);
    }
  };

  const filtered = rules.filter((x) =>
    `${x.rule_id} ${x.rule_name} ${x.description || ''}`
      .toLowerCase()
      .includes(q.toLowerCase())
  );

  return (
    <main className="page">
      <div className="eyebrow">DETECTION ENGINE</div>
      <div className="page-header">
        <div>
          <h1>Detection rules</h1>
          <p>Manage correlation rules and their runtime configuration.</p>
        </div>
        <button className="refresh" onClick={load} disabled={loading}>
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      {error && (
        <div className="api-warning" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <AlertCircle size={15} /> {error}
        </div>
      )}

      <div className="toolbar">
        <div className="search">
          <Search size={15} />
          <input
            placeholder="Search rules by name, ID or description..."
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
      </div>

      <div className="panel table-panel">
        <div className="table-meta">
          <span>{loading ? 'Loading…' : `${filtered.length} rules`}</span>
          <span>Role-protected updates (PUT /api/v1/rules)</span>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Rule Name & ID</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Parameters</th>
                <th>Updated</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((x) => {
                const isUpdatingRow = rowUpdatingId === x.rule_id;
                return (
                  <tr key={x.rule_id}>
                    <td>
                      <b>{x.rule_name}</b>
                      <small>
                        {x.rule_id}
                        {x.description && <><br />{x.description}</>}
                      </small>
                    </td>
                    <td>
                      <span className={`badge ${x.severity.toLowerCase()}`}>
                        {x.severity}
                      </span>
                    </td>
                    <td>
                      <button
                        onClick={() => handleToggleEnabled(x)}
                        disabled={isUpdatingRow}
                        className={`status ${x.enabled ? 'enabled' : 'disabled'}`}
                        style={{ cursor: 'pointer', border: '1px solid', padding: '4px 8px', display: 'inline-flex', alignItems: 'center', gap: 4 }}
                        title="Click to toggle enabled/disabled"
                      >
                        {isUpdatingRow ? (
                          <Loader2 size={11} className="animate-spin" />
                        ) : x.enabled ? (
                          <CheckCircle size={11} />
                        ) : (
                          <XCircle size={11} />
                        )}
                        {x.enabled ? 'ENABLED' : 'DISABLED'}
                      </button>
                    </td>
                    <td className="mono">
                      {Object.keys(x.parameters || {}).length} configured
                    </td>
                    <td className="mono">{new Date(x.updated_at).toLocaleString()}</td>
                    <td>
                      <button
                        className="refresh"
                        style={{ padding: '4px 9px', fontSize: '9px' }}
                        onClick={() => openEditModal(x)}
                      >
                        <Edit2 size={12} /> Edit
                      </button>
                    </td>
                  </tr>
                );
              })}
              {!loading && !filtered.length && (
                <tr>
                  <td colSpan={6}>
                    <div className="empty">No rules found matching search.</div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Edit Rule Modal */}
      {editingRule && (
        <div className="modal-overlay" onClick={() => setEditingRule(null)}>
          <div className="modal-box" onClick={(e) => e.stopPropagation()}>
            <div className="modal-head">
              <div>
                <h2>Edit Rule: {editingRule.rule_id}</h2>
                <p>Modify detection parameters and engine rule status.</p>
              </div>
              <button className="modal-close" onClick={() => setEditingRule(null)}>
                <X size={18} />
              </button>
            </div>

            {modalError && (
              <div className="inline-error" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <AlertCircle size={15} /> {modalError}
              </div>
            )}

            <form onSubmit={handleSaveRule}>
              <div className="modal-grid">
                <div className="modal-field full">
                  <label>RULE NAME</label>
                  <input
                    className="modal-input"
                    value={editName}
                    onChange={(e) => setEditName(e.target.value)}
                    required
                    style={{ width: '100%', background: '#05090d', border: '1px solid #1c2e39', padding: '8px', color: '#fff', borderRadius: '6px' }}
                  />
                </div>

                <div className="modal-field">
                  <label>SEVERITY</label>
                  <select
                    value={editSeverity}
                    onChange={(e) => setEditSeverity(e.target.value)}
                    style={{ width: '100%', background: '#05090d', border: '1px solid #1c2e39', padding: '8px', color: '#fff', borderRadius: '6px' }}
                  >
                    {SEVERITY_OPTIONS.map((sev) => (
                      <option key={sev} value={sev}>
                        {sev}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="modal-field">
                  <label>RULE STATUS</label>
                  <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8, cursor: 'pointer', color: '#dce8ec' }}>
                    <input
                      type="checkbox"
                      checked={editEnabled}
                      onChange={(e) => setEditEnabled(e.target.checked)}
                    />
                    Enable Detection Rule
                  </label>
                </div>

                <div className="modal-field full">
                  <label>DESCRIPTION</label>
                  <textarea
                    rows={2}
                    value={editDescription}
                    onChange={(e) => setEditDescription(e.target.value)}
                    style={{ width: '100%', background: '#05090d', border: '1px solid #1c2e39', padding: '8px', color: '#fff', borderRadius: '6px', fontFamily: 'inherit' }}
                  />
                </div>

                <div className="modal-field full">
                  <label>PARAMETERS (JSON OBJECT)</label>
                  <textarea
                    rows={6}
                    value={editParamsJson}
                    onChange={(e) => setEditParamsJson(e.target.value)}
                    style={{ width: '100%', background: '#04070b', border: '1px solid #1c2e39', padding: '10px', color: '#9eb4bf', borderRadius: '6px', fontFamily: 'DM Mono, monospace', fontSize: '11px' }}
                  />
                </div>
              </div>

              <div className="modal-actions">
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => setEditingRule(null)}
                  disabled={saving}
                >
                  Cancel
                </button>
                <button type="submit" className="btn-primary" disabled={saving}>
                  {saving ? 'Saving changes...' : 'Save Rule Configuration'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </main>
  );
}
