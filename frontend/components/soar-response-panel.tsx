'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { Check, ChevronDown, Clock3, Loader2, Play, Plus, RefreshCw, ShieldAlert, X } from 'lucide-react';
import { api } from '@/lib/api';

type SoarStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXECUTED';
type SoarActionType =
  | 'ADD_WATCHLIST'
  | 'COLLECT_FORENSICS'
  | 'REQUEST_RESCAN'
  | 'NOTIFY_ANALYST'
  | 'BLOCK_IP'
  | 'ISOLATE_HOST'
  | 'DISABLE_ACCOUNT'
  | 'KILL_PROCESS';

type TargetType = 'IP' | 'ASSET' | 'USER' | 'PROCESS' | 'INCIDENT';

type SoarAction = {
  action_id: string;
  incident_id: string;
  action_type: SoarActionType;
  target_type: TargetType;
  target_value: string;
  parameters: Record<string, unknown>;
  status: SoarStatus;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  reason: string;
  requested_by: string;
  approved_by?: string | null;
  rejected_by?: string | null;
  execution_result?: Record<string, unknown> | null;
  created_at: string;
  decided_at?: string | null;
  executed_at?: string | null;
  version: number;
};

type SoarAudit = {
  audit_id: string;
  action_id: string;
  actor: string;
  event: string;
  details: Record<string, unknown>;
  created_at: string;
};

const ACTIONS: { value: SoarActionType; label: string; target: TargetType; risk: SoarAction['risk_level'] }[] = [
  { value: 'COLLECT_FORENSICS', label: 'Collect forensics', target: 'ASSET', risk: 'LOW' },
  { value: 'REQUEST_RESCAN', label: 'Request rescan', target: 'ASSET', risk: 'LOW' },
  { value: 'ADD_WATCHLIST', label: 'Add IP to watchlist', target: 'IP', risk: 'LOW' },
  { value: 'NOTIFY_ANALYST', label: 'Notify analyst', target: 'INCIDENT', risk: 'LOW' },
  { value: 'BLOCK_IP', label: 'Block IP', target: 'IP', risk: 'HIGH' },
  { value: 'ISOLATE_HOST', label: 'Isolate host', target: 'ASSET', risk: 'CRITICAL' },
  { value: 'DISABLE_ACCOUNT', label: 'Disable account', target: 'USER', risk: 'CRITICAL' },
  { value: 'KILL_PROCESS', label: 'Kill process', target: 'PROCESS', risk: 'HIGH' },
];

function formatDate(value?: string | null) {
  if (!value) return '—';
  return new Intl.DateTimeFormat('en-GB', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' }).format(new Date(value));
}

export function SoarResponsePanel({
  incidentId,
  sourceIp,
  destinationIp,
}: {
  incidentId: string;
  sourceIp?: string | null;
  destinationIp?: string | null;
}) {
  const [actions, setActions] = useState<SoarAction[]>([]);
  const [selectedAction, setSelectedAction] = useState<SoarAction | null>(null);
  const [audit, setAudit] = useState<SoarAudit[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState('');
  const [creating, setCreating] = useState(false);
  const [actionType, setActionType] = useState<SoarActionType>('COLLECT_FORENSICS');
  const [target, setTarget] = useState(destinationIp || sourceIp || incidentId);
  const [reason, setReason] = useState('Analyst-requested response action for this incident.');

  const definition = useMemo(() => ACTIONS.find((item) => item.value === actionType) || ACTIONS[0], [actionType]);

  useEffect(() => {
    if (definition.target === 'IP') setTarget(sourceIp || destinationIp || '');
    else if (definition.target === 'INCIDENT') setTarget(incidentId);
    else if (definition.target === 'ASSET') setTarget(destinationIp || sourceIp || '');
    else setTarget('');
  }, [definition, destinationIp, incidentId, sourceIp]);

  const loadActions = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const data = await api<SoarAction[]>(`/soar/actions?incident_id=${encodeURIComponent(incidentId)}&limit=100`);
      setActions(data);
      if (selectedAction) {
        const fresh = data.find((x) => x.action_id === selectedAction.action_id) || null;
        setSelectedAction(fresh);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load SOAR actions.');
    } finally {
      setLoading(false);
    }
  }, [incidentId, selectedAction?.action_id]);

  useEffect(() => {
    void loadActions();
  }, [incidentId]);

  const loadAudit = async (action: SoarAction) => {
    setSelectedAction(action);
    setAudit([]);
    try {
      setAudit(await api<SoarAudit[]>(`/soar/actions/${action.action_id}/audit`));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load audit trail.');
    }
  };

  const createAction = async () => {
    if (!target.trim() || !reason.trim()) return;
    setCreating(true);
    setError('');
    try {
      await api<SoarAction>('/soar/actions', {
        method: 'POST',
        body: JSON.stringify({
          incident_id: incidentId,
          action_type: actionType,
          target_type: definition.target,
          target_value: target.trim(),
          parameters: {},
          risk_level: definition.risk,
          reason: reason.trim(),
        }),
      });
      await loadActions();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create response action.');
    } finally {
      setCreating(false);
    }
  };

  const transition = async (action: SoarAction, operation: 'approve' | 'reject' | 'execute') => {
    setBusyId(action.action_id);
    setError('');
    try {
      await api<SoarAction>(`/soar/actions/${action.action_id}/${operation}`, {
        method: 'POST',
        body: operation === 'execute' ? undefined : JSON.stringify({ note: `Analyst ${operation} decision from incident workspace.` }),
      });
      await loadActions();
      const fresh = await api<SoarAction>(`/soar/actions/${action.action_id}`);
      await loadAudit(fresh);
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to ${operation} action.`);
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="modal-field full" style={{ marginTop: 8 }}>
      <label>SOAR RESPONSE ACTIONS</label>
      <div style={{ border: '1px solid var(--border)', background: 'rgba(5,12,20,.55)', padding: 12, marginTop: 6 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <div>
            <b style={{ display: 'block' }}>Approval-based response</b>
            <small style={{ opacity: .7 }}>Controlled actions stay simulated until an analyst approves them and a real executor is enabled.</small>
          </div>
          <button className="refresh" onClick={() => void loadActions()} disabled={loading}>
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} /> Refresh
          </button>
        </div>

        {error && <div className="inline-error" style={{ marginTop: 10 }}>{error}</div>}

        <div style={{ display: 'grid', gridTemplateColumns: '1.2fr .8fr', gap: 8, marginTop: 12 }}>
          <div className="select-wrap">
            <select value={actionType} onChange={(e) => setActionType(e.target.value as SoarActionType)}>
              {ACTIONS.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
            </select>
            <ChevronDown size={14} />
          </div>
          <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder={`Target ${definition.target.toLowerCase()}`} style={{ width: '100%' }} />
        </div>
        <textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={2} style={{ width: '100%', marginTop: 8 }} />
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8, marginTop: 8 }}>
          <span className={`badge ${definition.risk.toLowerCase()}`}>RISK {definition.risk}</span>
          <button className="refresh" onClick={() => void createAction()} disabled={creating || !target.trim() || !reason.trim()}>
            {creating ? <Loader2 size={13} className="animate-spin" /> : <Plus size={13} />} Request action
          </button>
        </div>

        <div style={{ marginTop: 14, display: 'grid', gap: 8 }}>
          {actions.map((action) => {
            const busy = busyId === action.action_id;
            return (
              <div key={action.action_id} style={{ border: '1px solid var(--border)', padding: 10 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, alignItems: 'flex-start' }}>
                  <div>
                    <b>{action.action_type.replaceAll('_', ' ')}</b>
                    <small style={{ display: 'block', marginTop: 3 }}>{action.target_type}: <span className="mono">{action.target_value}</span></small>
                    <small style={{ display: 'block', marginTop: 3, opacity: .72 }}>{action.reason}</small>
                  </div>
                  <span className={`status ${action.status.toLowerCase()}`}>{action.status}</span>
                </div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 9 }}>
                  <button className="refresh" onClick={() => void loadAudit(action)}><Clock3 size={12} /> Audit</button>
                  {action.status === 'PENDING' && <>
                    <button className="refresh" onClick={() => void transition(action, 'approve')} disabled={busy}>{busy ? <Loader2 size={12} className="animate-spin" /> : <Check size={12} />} Approve</button>
                    <button className="refresh" onClick={() => void transition(action, 'reject')} disabled={busy}><X size={12} /> Reject</button>
                  </>}
                  {action.status === 'APPROVED' && <button className="refresh" onClick={() => void transition(action, 'execute')} disabled={busy}>{busy ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} />} Execute</button>}
                  {action.status === 'EXECUTED' && action.execution_result?.mode && <span className="soon-badge"><ShieldAlert size={11} /> {String(action.execution_result.mode)}</span>}
                </div>
              </div>
            );
          })}
          {!loading && actions.length === 0 && <div className="empty">No response actions requested for this incident.</div>}
        </div>

        {selectedAction && (
          <div style={{ marginTop: 14, borderTop: '1px solid var(--border)', paddingTop: 12 }}>
            <b>Audit timeline — {selectedAction.action_type.replaceAll('_', ' ')}</b>
            <div style={{ marginTop: 8, display: 'grid', gap: 6 }}>
              {audit.map((entry) => (
                <div key={entry.audit_id} style={{ display: 'grid', gridTemplateColumns: '120px 110px 1fr', gap: 8, fontSize: 11 }}>
                  <span className="mono">{formatDate(entry.created_at)}</span>
                  <b>{entry.event}</b>
                  <span>{entry.actor} · {JSON.stringify(entry.details)}</span>
                </div>
              ))}
              {audit.length === 0 && <small style={{ opacity: .7 }}>No audit entries loaded.</small>}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
