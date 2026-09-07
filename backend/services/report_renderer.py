"""Professional, printable SOC incident report rendering."""
from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from typing import Any


def _text(value: Any) -> str:
    return escape(str(value if value not in (None, "") else "—"))


def _chips(values: list[Any] | None, kind: str = "") -> str:
    if not values:
        return '<div class="empty">No evidence recorded.</div>'
    rows = []
    for value in values:
        if isinstance(value, dict):
            value = value.get("name") or value.get("technique") or value.get("value") or value
        rows.append(f'<span class="chip {kind}">{_text(value)}</span>')
    return '<div class="chips">' + "".join(rows) + "</div>"


def _findings(values: list[Any] | None) -> str:
    if not values:
        return '<div class="empty">No findings recorded.</div>'
    return '<div class="findings">' + "".join(
        f'<div class="finding"><span class="finding-dot"></span><span>{_text(v)}</span></div>' for v in values
    ) + '</div>'


def _detail_html(value: Any) -> str:
    if isinstance(value, dict):
        parts = []
        for key, item in value.items():
            if isinstance(item, dict):
                nested = "".join(
                    f'<div class="detail-line"><span class="detail-key">{_text(k)}</span><span>{_text(v)}</span></div>'
                    for k, v in item.items()
                )
                parts.append(f'<div class="detail-group"><div class="detail-key">{_text(key)}</div>{nested}</div>')
            else:
                parts.append(f'<div class="detail-line"><span class="detail-key">{_text(key)}</span><span>{_text(item)}</span></div>')
        return "".join(parts) or '<span class="muted">—</span>'
    return _text(value)


def _status_class(value: Any) -> str:
    status = str(value or "").upper()
    if status in {"EXECUTED", "COMPLETED", "RESOLVED", "CLOSED"}:
        return "success"
    if status in {"PENDING", "APPROVED", "OPEN", "INVESTIGATING"}:
        return "warning"
    if status in {"FAILED", "REJECTED", "CRITICAL"}:
        return "danger"
    return "neutral"


def render_incident_report(report: dict[str, Any], *, soar_actions: list[dict[str, Any]] | None = None,
                           timeline: list[dict[str, Any]] | None = None,
                           vulnerability_evidence: list[dict[str, Any]] | None = None) -> str:
    actions = soar_actions or []
    timeline_rows = timeline or []
    vulns = vulnerability_evidence or []
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")
    severity = str(report.get("severity") or "UNKNOWN").upper()
    risk = report.get("overall_risk_score")
    confidence = report.get("confidence_score")

    action_rows = "".join(
        f'''<tr><td><b>{_text(a.get('action_type'))}</b></td><td>{_text(a.get('target_value'))}</td>
        <td><span class="badge {_status_class(a.get('status'))}">{_text(a.get('status'))}</span></td>
        <td>{_text(a.get('approved_by') or a.get('rejected_by'))}</td></tr>''' for a in actions
    ) or '<tr><td colspan="4" class="empty">No response actions recorded.</td></tr>'

    timeline_html = "".join(
        f'''<div class="timeline-item"><div class="timeline-marker"></div><div class="timeline-card">
        <div class="timeline-head"><span class="badge {_status_class(i.get('event'))}">{_text(i.get('event'))}</span>
        <span class="timeline-time">{_text(i.get('timestamp'))}</span></div>
        <div class="timeline-actor">{_text(i.get('actor'))}</div><div class="timeline-details">{_detail_html(i.get('details'))}</div>
        </div></div>''' for i in timeline_rows
    ) or '<div class="empty">No response timeline events recorded.</div>'

    vuln_rows = "".join(
        f'''<tr><td><b>{_text(v.get('cve_id'))}</b><br><span class="muted">{_text(v.get('severity'))} · CVSS {_text(v.get('cvss_score'))}</span></td>
        <td>{_text(v.get('agent_id'))}<br><span class="muted">{_text(v.get('matched_software'))}</span></td>
        <td>{_text(v.get('exposure_status'))}<br><span class="muted">Risk {_text(v.get('risk_score'))} · Confidence {_text(v.get('match_confidence'))}</span></td>
        <td>KEV {_text(v.get('known_exploited'))} · Exploit {_text(v.get('exploit_available'))} · Internet {_text(v.get('internet_exposed'))}</td>
        <td>{_text(v.get('event_evidence_score'))}<br><span class="muted">{_text(v.get('rationale'))}</span></td></tr>''' for v in vulns
    ) or '<tr><td colspan="5" class="empty">No deterministic CVE exposure is linked to this incident.</td></tr>'

    return f'''<!doctype html><html><head><meta charset="utf-8"><title>{_text(report.get("report_id"))} — SanitialX</title><style>
@page{{size:A4;margin:15mm 14mm 17mm}}
*{{box-sizing:border-box}}html,body{{padding:0;margin:0}}
:root{{--navy:#081426;--navy2:#0d2038;--blue:#2563eb;--cyan:#0891b2;--red:#dc2626;--orange:#ea580c;--green:#16a34a;--ink:#172033;--muted:#64748b;--line:#dbe3ee;--soft:#f4f7fb}}
body{{font-family:Inter,"Segoe UI",Arial,sans-serif;color:var(--ink);background:#edf2f7;font-size:11px;line-height:1.5}}
.report{{max-width:960px;margin:24px auto;background:white;box-shadow:0 18px 60px #0f172a20}}
.hero{{background:linear-gradient(125deg,var(--navy),var(--navy2));color:white;padding:28px 30px 24px;position:relative;overflow:hidden}}
.hero:after{{content:"";position:absolute;width:230px;height:230px;border:1px solid #38bdf833;border-radius:50%;right:-65px;top:-105px;box-shadow:0 0 0 34px #38bdf80d,0 0 0 70px #38bdf808}}
.hero-top{{display:flex;justify-content:space-between;gap:30px;position:relative;z-index:1}}.brand{{font-size:12px;font-weight:800;letter-spacing:2.2px;color:#67e8f9}}.eyebrow{{font-size:9px;letter-spacing:1.4px;text-transform:uppercase;color:#94a3b8;margin-top:8px}}
h1{{font-size:27px;line-height:1.15;margin:5px 0 7px;letter-spacing:-.5px}}.report-id{{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:#cbd5e1}}
.hero-meta{{text-align:right;min-width:190px;font-size:10px;color:#cbd5e1}}.hero-meta b{{color:white}}
.classification{{display:inline-block;margin-top:8px;border:1px solid #fca5a566;background:#ef44441a;color:#fecaca;border-radius:999px;padding:4px 9px;font-size:8px;font-weight:800;letter-spacing:1px}}
.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;padding:0 30px;transform:translateY(-12px);position:relative;z-index:2}}
.metric{{background:white;border:1px solid var(--line);border-radius:10px;padding:12px 13px;box-shadow:0 8px 20px #0f172a12}}.metric-label{{font-size:8px;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);font-weight:700}}.metric-value{{font-size:18px;font-weight:800;margin-top:2px}}.metric-value.big{{font-size:25px;line-height:1}}
.badge{{display:inline-block;border-radius:999px;padding:3px 8px;font-size:8px;font-weight:800;letter-spacing:.45px;text-transform:uppercase}}.danger{{background:#fee2e2;color:#b91c1c}}.warning{{background:#ffedd5;color:#c2410c}}.success{{background:#dcfce7;color:#15803d}}.neutral{{background:#e2e8f0;color:#475569}}
.meter{{height:5px;background:#e2e8f0;border-radius:99px;margin-top:7px;overflow:hidden}}.meter span{{display:block;height:100%;background:linear-gradient(90deg,#0ea5e9,#2563eb);border-radius:99px}}.meter.risk span{{background:linear-gradient(90deg,#f97316,#dc2626)}}
.content{{padding:5px 30px 28px}}section{{margin:20px 0;break-inside:auto}}.section-title{{display:flex;align-items:center;gap:9px;margin-bottom:9px}}.section-index{{font:700 8px ui-monospace,monospace;color:var(--blue);background:#dbeafe;padding:3px 6px;border-radius:4px}}h2{{font-size:14px;margin:0;letter-spacing:-.15px}}
.summary{{border:1px solid #bfdbfe;background:linear-gradient(135deg,#eff6ff,#f8fafc);border-radius:10px;padding:14px 16px;font-size:11.5px;position:relative}}.summary:before{{content:"AI SOC ANALYSIS";display:block;font-size:8px;font-weight:800;letter-spacing:1px;color:var(--blue);margin-bottom:5px}}
.meta-grid{{display:grid;grid-template-columns:repeat(2,1fr);border:1px solid var(--line);border-radius:9px;overflow:hidden}}.meta{{padding:9px 11px;border-bottom:1px solid var(--line)}}.meta:nth-child(odd){{border-right:1px solid var(--line)}}.meta-label{{font-size:8px;text-transform:uppercase;color:var(--muted);font-weight:700}}.meta-value{{font-weight:650;margin-top:2px;overflow-wrap:anywhere}}
.findings{{display:grid;gap:6px}}.finding{{display:flex;gap:9px;padding:8px 10px;background:var(--soft);border-radius:7px}}.finding-dot{{width:6px;height:6px;margin-top:5px;border-radius:50%;background:var(--blue);flex:none}}
.chips{{display:flex;flex-wrap:wrap;gap:6px}}.chip{{display:inline-flex;padding:4px 8px;border-radius:6px;background:#eef2f7;border:1px solid #dbe3ee;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:9px;font-weight:650}}.chip.ioc{{background:#fff1f2;border-color:#fecdd3;color:#9f1239}}.chip.mitre{{background:#eef2ff;border-color:#c7d2fe;color:#3730a3}}
table{{width:100%;border-collapse:separate;border-spacing:0;border:1px solid var(--line);border-radius:8px;overflow:hidden;table-layout:fixed}}th,td{{padding:7px 8px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line);overflow-wrap:anywhere;word-break:break-word}}th{{background:#f1f5f9;font-size:8px;text-transform:uppercase;letter-spacing:.5px;color:#475569}}tr:last-child td{{border-bottom:0}}.muted,.empty{{color:var(--muted)}}
.context-grid{{display:grid;grid-template-columns:1fr 1fr;gap:8px}}.context-card{{border:1px solid var(--line);border-radius:8px;padding:10px}}.context-label{{font-size:8px;color:var(--muted);text-transform:uppercase;font-weight:700}}.context-value{{font-weight:650;margin-top:3px}}
.timeline{{position:relative;margin-left:5px}}.timeline:before{{content:"";position:absolute;left:5px;top:8px;bottom:8px;width:1px;background:#cbd5e1}}.timeline-item{{position:relative;padding-left:24px;margin:0 0 9px}}.timeline-marker{{position:absolute;left:0;top:9px;width:11px;height:11px;background:white;border:3px solid var(--blue);border-radius:50%;z-index:1}}.timeline-card{{border:1px solid var(--line);border-radius:8px;padding:9px 11px;background:#fff}}.timeline-head{{display:flex;justify-content:space-between;gap:12px;align-items:center}}.timeline-time{{font:8px ui-monospace,monospace;color:var(--muted)}}.timeline-actor{{font-size:9px;font-weight:700;color:#334155;margin:5px 0}}.timeline-details{{font-size:9px;color:#475569}}.detail-line{{display:grid;grid-template-columns:minmax(90px,28%) 1fr;gap:7px;margin:2px 0}}.detail-key{{font-weight:700;color:#334155}}.detail-group{{margin-top:4px;padding-top:4px;border-top:1px dashed var(--line)}}
.remediation{{counter-reset:remedy;display:grid;gap:7px}}.remedy{{counter-increment:remedy;display:grid;grid-template-columns:25px 1fr;gap:9px;align-items:start;border:1px solid var(--line);border-radius:8px;padding:8px}}.remedy:before{{content:counter(remedy);display:grid;place-items:center;width:22px;height:22px;border-radius:6px;background:var(--navy);color:white;font-weight:800;font-size:9px}}
.footer{{background:#f8fafc;border-top:1px solid var(--line);padding:12px 30px;color:var(--muted);font-size:8px;display:flex;justify-content:space-between;gap:20px}}
@media print{{body{{background:white}}.report{{margin:0;max-width:none;box-shadow:none}}.hero{{print-color-adjust:exact;-webkit-print-color-adjust:exact}}.metrics{{print-color-adjust:exact;-webkit-print-color-adjust:exact}}.content{{padding-left:0;padding-right:0}}.hero{{margin-left:0;margin-right:0}}section,.metric,.timeline-card,tr{{break-inside:avoid}}}}
@media screen and (max-width:720px){{.report{{margin:0}}.hero-top{{display:block}}.hero-meta{{text-align:left;margin-top:16px}}.metrics{{grid-template-columns:1fr 1fr;padding:0 16px}}.content{{padding:5px 16px 24px}}.meta-grid,.context-grid{{grid-template-columns:1fr}}.meta:nth-child(odd){{border-right:0}}}}
</style></head><body><main class="report">
<div class="hero"><div class="hero-top"><div><div class="brand">SANITIALX SOC</div><div class="eyebrow">Security Operations Center · Incident Intelligence</div><h1>Incident Investigation Report</h1><div class="report-id">{_text(report.get('report_id'))}</div></div><div class="hero-meta"><b>Generated</b><br>{_text(generated)}<br><span class="classification">CONFIDENTIAL · SOC USE</span></div></div></div>
<div class="metrics"><div class="metric"><div class="metric-label">Severity</div><div class="metric-value"><span class="badge danger">{_text(severity)}</span></div></div><div class="metric"><div class="metric-label">Incident status</div><div class="metric-value"><span class="badge {_status_class(report.get('status'))}">{_text(report.get('status'))}</span></div></div><div class="metric"><div class="metric-label">AI confidence</div><div class="metric-value big">{_text(confidence)}<span style="font-size:10px;color:#64748b">%</span></div><div class="meter"><span style="width:{_text(confidence)}%"></span></div></div><div class="metric"><div class="metric-label">Risk score</div><div class="metric-value big">{_text(risk)}<span style="font-size:10px;color:#64748b">/100</span></div><div class="meter risk"><span style="width:{_text(risk)}%"></span></div></div></div>
<div class="content">
<section><div class="section-title"><span class="section-index">01</span><h2>Executive Summary</h2></div><div class="summary">{_text(report.get('executive_summary'))}</div></section>
<section><div class="section-title"><span class="section-index">02</span><h2>Incident Metadata</h2></div><div class="meta-grid"><div class="meta"><div class="meta-label">Incident ID</div><div class="meta-value">{_text(report.get('incident_id'))}</div></div><div class="meta"><div class="meta-label">Classification</div><div class="meta-value">{_text(report.get('threat_classification'))}</div></div><div class="meta"><div class="meta-label">Source IP</div><div class="meta-value">{_text(report.get('source_ip'))}</div></div><div class="meta"><div class="meta-label">Destination IP</div><div class="meta-value">{_text(report.get('destination_ip'))}</div></div><div class="meta"><div class="meta-label">Created</div><div class="meta-value">{_text(report.get('created_at'))}</div></div><div class="meta"><div class="meta-label">Updated</div><div class="meta-value">{_text(report.get('updated_at'))}</div></div></div></section>
<section><div class="section-title"><span class="section-index">03</span><h2>Key Findings</h2></div>{_findings(report.get('key_findings'))}</section>
<section><div class="section-title"><span class="section-index">04</span><h2>Indicators & Techniques</h2></div><div class="context-grid"><div class="context-card"><div class="context-label">Indicators of Compromise</div><div style="margin-top:7px">{_chips(report.get('indicators_of_compromise'),'ioc')}</div></div><div class="context-card"><div class="context-label">MITRE ATT&CK Techniques</div><div style="margin-top:7px">{_chips(report.get('observed_techniques'),'mitre')}</div></div></div><div class="context-card" style="margin-top:8px"><div class="context-label">Affected Assets</div><div style="margin-top:7px">{_chips(report.get('affected_assets'))}</div></div></section>
<section><div class="section-title"><span class="section-index">05</span><h2>Attack Context</h2></div><div class="context-grid"><div class="context-card"><div class="context-label">Initial access vector</div><div class="context-value">{_text(report.get('initial_access_vector'))}</div></div><div class="context-card"><div class="context-label">Honeypot engagement</div><div class="context-value">{_text(report.get('honeypot_engagement'))}</div></div><div class="context-card"><div class="context-label">Simulated data loss</div><div class="context-value">{_text(report.get('simulated_data_loss'))}</div></div><div class="context-card"><div class="context-label">Detection IDs</div><div class="context-value">{_text(', '.join(report.get('triggering_detection_ids') or []))}</div></div></div></section>
<section><div class="section-title"><span class="section-index">06</span><h2>Asset / CVE Exposure Evidence</h2></div><table><thead><tr><th>CVE</th><th>Asset / Software</th><th>Exposure</th><th>Threat Intel</th><th>Event Evidence</th></tr></thead><tbody>{vuln_rows}</tbody></table></section>
<section><div class="section-title"><span class="section-index">07</span><h2>Response Timeline</h2></div><div class="timeline">{timeline_html}</div></section>
<section><div class="section-title"><span class="section-index">08</span><h2>SOAR Response Actions</h2></div><table><thead><tr><th>Action</th><th>Target</th><th>Status</th><th>Decision actor</th></tr></thead><tbody>{action_rows}</tbody></table></section>
<section><div class="section-title"><span class="section-index">09</span><h2>Recommended Remediation</h2></div><div class="remediation">{"".join(f'<div class="remedy"><span>{_text(v)}</span></div>' for v in (report.get('recommended_actions') or [])) or '<div class="empty">No remediation recorded.</div>'}</div></section>
</div><div class="footer"><span>Generated by SanitialX Professional Reporting · AI analysis requires analyst validation.</span><span>{_text(report.get('report_id'))} · CONFIDENTIAL</span></div></main></body></html>'''
