"""Professional, printable SOC incident report rendering."""
from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from typing import Any


def _text(value: Any) -> str:
    return escape(str(value if value not in (None, "") else "—"))


def _items(values: list[Any] | None, css_class: str = "bullet-list") -> str:
    if not values:
        return '<div class="empty">No evidence recorded.</div>'
    rows = []
    for value in values:
        if isinstance(value, dict):
            value = value.get("name") or value.get("technique") or value.get("value") or value
        rows.append(f"<li>{_text(value)}</li>")
    return f'<ul class="{css_class}">' + "".join(rows) + "</ul>"


def _chips(values: list[Any] | None, kind: str = "default") -> str:
    if not values:
        return '<span class="muted">No evidence recorded.</span>'
    chips = []
    for value in values:
        if isinstance(value, dict):
            value = value.get("name") or value.get("technique") or value.get("value") or value
        chips.append(f'<span class="chip chip-{kind}">{_text(value)}</span>')
    return '<div class="chips">' + "".join(chips) + "</div>"


def _detail_html(value: Any) -> str:
    if isinstance(value, dict):
        parts = []
        for key, item in value.items():
            if isinstance(item, dict):
                nested = "".join(
                    f'<div class="detail-line"><span class="detail-key">{_text(nested_key)}</span><span>{_text(nested_value)}</span></div>'
                    for nested_key, nested_value in item.items()
                )
                parts.append(f'<div class="detail-group"><div class="detail-key">{_text(key)}</div>{nested}</div>')
            else:
                parts.append(f'<div class="detail-line"><span class="detail-key">{_text(key)}</span><span>{_text(item)}</span></div>')
        return "".join(parts) or '<span class="muted">—</span>'
    return _text(value)


def _status_class(value: Any) -> str:
    return str(value or "").strip().lower().replace("_", "-")


def render_incident_report(
    report: dict[str, Any],
    *,
    soar_actions: list[dict[str, Any]] | None = None,
    timeline: list[dict[str, Any]] | None = None,
    vulnerability_evidence: list[dict[str, Any]] | None = None,
) -> str:
    actions = soar_actions or []
    timeline_rows = timeline or []
    vulns = vulnerability_evidence or []
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")
    severity = str(report.get("severity") or "UNKNOWN").upper()
    status = str(report.get("status") or "UNKNOWN").upper()
    confidence = report.get("confidence_score")
    risk = report.get("overall_risk_score")

    action_rows = "".join(
        f'''<div class="action-row"><div><div class="action-name">{_text(a.get('action_type'))}</div><div class="action-target">{_text(a.get('target_value'))}</div></div><span class="status-pill status-{_status_class(a.get('status'))}">{_text(a.get('status'))}</span><div class="action-actor">{_text(a.get('approved_by') or a.get('rejected_by'))}</div></div>'''
        for a in actions
    ) or '<div class="empty">No response actions recorded.</div>'

    timeline_html = "".join(
        f'''<div class="timeline-item"><div class="timeline-marker"></div><div class="timeline-body"><div class="timeline-top"><span class="timeline-event">{_text(i.get('event'))}</span><span class="timeline-time">{_text(i.get('timestamp'))}</span></div><div class="timeline-actor">{_text(i.get('actor'))}</div><div class="timeline-details">{_detail_html(i.get('details'))}</div></div></div>'''
        for i in timeline_rows
    ) or '<div class="empty">No response timeline events recorded.</div>'

    vuln_rows = "".join(
        f"<tr><td><b>{_text(v.get('cve_id'))}</b><br><span class='muted'>{_text(v.get('severity'))} · CVSS {_text(v.get('cvss_score'))}</span></td><td>{_text(v.get('agent_id'))}<br>{_text(v.get('matched_software'))}</td><td>{_text(v.get('exposure_status'))}<br><span class='muted'>Risk {_text(v.get('risk_score'))} · Confidence {_text(v.get('match_confidence'))}</span></td><td>KEV {_text(v.get('known_exploited'))}<br>Exploit {_text(v.get('exploit_available'))}<br>Internet {_text(v.get('internet_exposed'))}</td><td>{_text(v.get('event_evidence_score'))}<br>{_text(v.get('rationale'))}</td></tr>"
        for v in vulns
    ) or '<tr><td colspan="5" class="empty-cell">No deterministic CVE exposure is linked to this incident.</td></tr>'

    return f'''<!doctype html><html><head><meta charset="utf-8"><title>{_text(report.get("report_id"))} — SanitialX SOC</title><style>
@page{{size:A4;margin:15mm 14mm 17mm}}
*{{box-sizing:border-box}}
:root{{--navy:#081525;--navy2:#10233d;--ink:#182235;--muted:#66758a;--line:#dbe3ed;--soft:#f5f8fc;--blue:#2563eb;--cyan:#0891b2;--red:#dc2626;--redsoft:#fff1f2;--green:#15803d;--greensoft:#ecfdf3;--amber:#b45309}}
html,body{{padding:0;margin:0}}
body{{font-family:Inter,"Segoe UI",Arial,sans-serif;color:var(--ink);background:#e9eef5;font-size:11px;line-height:1.55;-webkit-print-color-adjust:exact;print-color-adjust:exact}}
.report{{width:min(100%,980px);margin:28px auto;background:white;box-shadow:0 16px 50px rgba(8,21,37,.14)}}
.hero{{background:linear-gradient(135deg,var(--navy),var(--navy2));color:#fff;padding:30px 34px 26px;position:relative;overflow:hidden}}
.hero:after{{content:"";position:absolute;width:240px;height:240px;border:1px solid rgba(89,191,255,.15);border-radius:50%;right:-80px;top:-125px;box-shadow:0 0 0 38px rgba(89,191,255,.035),0 0 0 76px rgba(89,191,255,.025)}}
.hero-top{{display:flex;justify-content:space-between;gap:24px;position:relative;z-index:1}}
.brand{{font-size:12px;font-weight:800;letter-spacing:2px;color:#7dd3fc;text-transform:uppercase}}
h1{{font-size:27px;line-height:1.15;margin:8px 0 7px;letter-spacing:-.4px}}
.report-id{{color:#b8c7da;font-family:ui-monospace,SFMono-Regular,Consolas,monospace}}
.hero-meta{{text-align:right;color:#c8d4e3;font-size:10px;min-width:210px}}
.confidential{{display:inline-block;margin-top:8px;border:1px solid rgba(255,255,255,.24);border-radius:999px;padding:4px 9px;font-weight:700;letter-spacing:.5px;color:#fff}}
.metrics{{display:grid;grid-template-columns:1.15fr 1fr 1fr 1fr;gap:10px;padding:0 34px;transform:translateY(-14px);position:relative;z-index:2}}
.metric{{background:#fff;border:1px solid var(--line);border-radius:10px;padding:13px 14px;box-shadow:0 6px 18px rgba(8,21,37,.08)}}
.metric-label{{font-size:8px;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);font-weight:700}}
.metric-value{{font-size:15px;font-weight:800;margin-top:4px}}
.metric-big{{font-size:24px;line-height:1}}
.severity-critical{{color:var(--red)}}.severity-high{{color:#ea580c}}.severity-medium{{color:var(--amber)}}.severity-low{{color:var(--green)}}
.progress{{height:5px;background:#e7edf5;border-radius:999px;margin-top:8px;overflow:hidden}}.progress>span{{display:block;height:100%;background:linear-gradient(90deg,#2563eb,#06b6d4);border-radius:inherit}}
.content{{padding:4px 34px 32px}}
.section{{margin-top:22px;break-inside:avoid-page}}
.section-title{{display:flex;align-items:center;gap:9px;font-size:14px;font-weight:800;margin:0 0 10px;color:#142033}}
.section-title:before{{content:"";width:4px;height:17px;border-radius:3px;background:var(--blue)}}
.summary{{background:linear-gradient(90deg,#f3f7ff,#f8fbff);border:1px solid #d9e5f6;border-left:4px solid var(--blue);border-radius:8px;padding:14px 16px;font-size:11.5px}}
.meta-grid{{display:grid;grid-template-columns:repeat(2,1fr);border:1px solid var(--line);border-radius:8px;overflow:hidden}}
.meta-item{{display:grid;grid-template-columns:120px 1fr;min-height:37px;border-bottom:1px solid var(--line)}}.meta-item:nth-child(odd){{border-right:1px solid var(--line)}}.meta-item:nth-last-child(-n+2){{border-bottom:0}}
.meta-key{{padding:9px 10px;background:var(--soft);font-weight:700}}.meta-value{{padding:9px 11px;overflow-wrap:anywhere}}
.two-col{{display:grid;grid-template-columns:1fr 1fr;gap:18px;align-items:start}}
.panel{{border:1px solid var(--line);border-radius:8px;padding:13px 15px;background:#fff}}
.panel-title{{font-weight:800;margin-bottom:9px;color:#344054}}
.bullet-list{{padding-left:18px;margin:0}}.bullet-list li{{margin:5px 0;padding-left:2px}}
.chips{{display:flex;flex-wrap:wrap;gap:6px}}.chip{{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;border-radius:999px;padding:4px 8px;border:1px solid #cfd9e7;background:#f8fafc;font-size:9.5px;font-weight:700}}.chip-ioc{{color:#9f1239;background:#fff1f2;border-color:#fecdd3}}.chip-mitre{{color:#1d4ed8;background:#eff6ff;border-color:#bfdbfe}}.chip-asset{{color:#0f766e;background:#f0fdfa;border-color:#99f6e4}}
table{{width:100%;border-collapse:separate;border-spacing:0;border:1px solid var(--line);border-radius:8px;overflow:hidden;table-layout:fixed}}th,td{{padding:8px 9px;text-align:left;vertical-align:top;border-right:1px solid var(--line);border-bottom:1px solid var(--line);overflow-wrap:anywhere}}th:last-child,td:last-child{{border-right:0}}tr:last-child td{{border-bottom:0}}th{{background:var(--soft);font-size:9px;text-transform:uppercase;letter-spacing:.45px;color:#475467}}tr{{break-inside:avoid}}
.context-table th{{width:165px;text-transform:none;font-size:10px;letter-spacing:0}}
.timeline{{position:relative;margin-left:8px}}.timeline:before{{content:"";position:absolute;left:6px;top:8px;bottom:8px;width:2px;background:#dbe5f0}}.timeline-item{{display:grid;grid-template-columns:14px 1fr;gap:12px;position:relative;padding:0 0 13px;break-inside:avoid}}.timeline-marker{{width:14px;height:14px;border:3px solid #fff;background:var(--blue);border-radius:50%;box-shadow:0 0 0 1px #9db9e8;z-index:1;margin-top:3px}}.timeline-body{{border:1px solid var(--line);border-radius:8px;padding:9px 11px;background:#fbfcfe}}.timeline-top{{display:flex;justify-content:space-between;gap:15px}}.timeline-event{{font-weight:800;color:#1e40af}}.timeline-time{{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--muted);font-size:9px}}.timeline-actor{{color:#475467;font-size:9.5px;margin:2px 0 5px}}.timeline-details{{font-size:9.5px;overflow-wrap:anywhere}}
.detail-line{{display:grid;grid-template-columns:minmax(90px,25%) 1fr;gap:8px;margin:2px 0}}.detail-key{{font-weight:700;color:#475467}}.detail-group{{margin:5px 0;padding-top:5px;border-top:1px dashed #dbe3ed}}
.actions{{display:grid;gap:7px}}.action-row{{display:grid;grid-template-columns:1fr auto 130px;align-items:center;gap:12px;border:1px solid var(--line);border-radius:8px;padding:10px 12px}}.action-name{{font-weight:800}}.action-target{{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--muted);font-size:9px;margin-top:2px}}.action-actor{{text-align:right;color:#475467}}.status-pill{{font-size:8.5px;font-weight:800;border-radius:999px;padding:4px 8px;letter-spacing:.4px}}.status-executed,.status-completed{{background:var(--greensoft);color:var(--green);border:1px solid #bbf7d0}}.status-approved{{background:#eff6ff;color:#1d4ed8;border:1px solid #bfdbfe}}.status-pending{{background:#fffbeb;color:#92400e;border:1px solid #fde68a}}
.remediation{{counter-reset:step;list-style:none;padding:0;margin:0;display:grid;gap:7px}}.remediation li{{counter-increment:step;position:relative;padding:9px 11px 9px 42px;border:1px solid var(--line);border-radius:8px;background:#fbfcfe}}.remediation li:before{{content:counter(step);position:absolute;left:11px;top:8px;width:21px;height:21px;border-radius:6px;background:#e8efff;color:#1d4ed8;display:grid;place-items:center;font-weight:800}}
.empty,.empty-cell{{color:var(--muted);font-style:italic}}.muted{{color:var(--muted)}}
.footer{{margin-top:28px;padding:15px 34px;background:#f4f7fb;border-top:1px solid var(--line);display:flex;justify-content:space-between;gap:20px;color:#66758a;font-size:8.5px}}.footer strong{{color:#344054}}
@media print{{body{{background:#fff}}.report{{width:auto;margin:0;box-shadow:none}}.hero{{padding:22px 22px 20px}}.metrics{{padding:0 22px}}.content{{padding-left:22px;padding-right:22px}}.footer{{padding-left:22px;padding-right:22px}}}}
@media(max-width:720px){{.report{{margin:0}}.hero-top,.two-col{{grid-template-columns:1fr;display:grid}}.hero-meta{{text-align:left}}.metrics{{grid-template-columns:1fr 1fr;padding:0 18px}}.content{{padding:4px 18px 28px}}.meta-grid{{grid-template-columns:1fr}}.meta-item:nth-child(odd){{border-right:0}}.action-row{{grid-template-columns:1fr auto}}.action-actor{{grid-column:1/-1;text-align:left}}}}
</style></head><body><main class="report">
<section class="hero"><div class="hero-top"><div><div class="brand">SanitialX · Security Operations Center</div><h1>Incident Investigation Report</h1><div class="report-id">{_text(report.get('report_id'))}</div></div><div class="hero-meta"><b>Generated</b><br>{_text(generated)}<br><span class="confidential">CONFIDENTIAL · SOC USE</span></div></div></section>
<div class="metrics"><div class="metric"><div class="metric-label">Severity</div><div class="metric-value severity-{_status_class(severity)}">{_text(severity)}</div></div><div class="metric"><div class="metric-label">Incident status</div><div class="metric-value">{_text(status)}</div></div><div class="metric"><div class="metric-label">AI confidence</div><div class="metric-value">{_text(confidence)}%</div><div class="progress"><span style="width:{_text(confidence)}%"></span></div></div><div class="metric"><div class="metric-label">Risk score</div><div class="metric-value metric-big">{_text(risk)}<span class="muted" style="font-size:10px"> / 100</span></div></div></div>
<div class="content">
<section class="section"><h2 class="section-title">Executive Summary</h2><div class="summary">{_text(report.get('executive_summary'))}</div></section>
<section class="section"><h2 class="section-title">Incident Metadata</h2><div class="meta-grid"><div class="meta-item"><div class="meta-key">Incident</div><div class="meta-value">{_text(report.get('incident_id'))}</div></div><div class="meta-item"><div class="meta-key">Title</div><div class="meta-value">{_text(report.get('title'))}</div></div><div class="meta-item"><div class="meta-key">Created</div><div class="meta-value">{_text(report.get('created_at'))}</div></div><div class="meta-item"><div class="meta-key">Updated</div><div class="meta-value">{_text(report.get('updated_at'))}</div></div><div class="meta-item"><div class="meta-key">Source IP</div><div class="meta-value">{_text(report.get('source_ip'))}</div></div><div class="meta-item"><div class="meta-key">Destination IP</div><div class="meta-value">{_text(report.get('destination_ip'))}</div></div></div></section>
<section class="section two-col"><div class="panel"><div class="panel-title">Key Findings</div>{_items(report.get('key_findings'))}</div><div class="panel"><div class="panel-title">Classification</div><div>{_text(report.get('threat_classification'))}</div><div style="margin-top:12px" class="panel-title">Initial Access</div><div>{_text(report.get('initial_access_vector'))}</div></div></section>
<section class="section two-col"><div><h2 class="section-title">Indicators of Compromise</h2>{_chips(report.get('indicators_of_compromise'),'ioc')}</div><div><h2 class="section-title">Affected Assets</h2>{_chips(report.get('affected_assets'),'asset')}</div></section>
<section class="section"><h2 class="section-title">MITRE ATT&CK Techniques</h2>{_chips(report.get('observed_techniques'),'mitre')}</section>
<section class="section"><h2 class="section-title">Attack Context</h2><table class="context-table"><tr><th>Initial access vector</th><td>{_text(report.get('initial_access_vector'))}</td></tr><tr><th>Honeypot engagement</th><td>{_text(report.get('honeypot_engagement'))}</td></tr><tr><th>Simulated data loss</th><td>{_text(report.get('simulated_data_loss'))}</td></tr><tr><th>Detection IDs</th><td>{_text(', '.join(report.get('triggering_detection_ids') or []))}</td></tr></table></section>
<section class="section"><h2 class="section-title">Asset / CVE Exposure Evidence</h2><table><thead><tr><th>CVE</th><th>Asset / Software</th><th>Exposure</th><th>Threat Intel</th><th>Event Evidence</th></tr></thead><tbody>{vuln_rows}</tbody></table></section>
<section class="section"><h2 class="section-title">Response Timeline</h2><div class="timeline">{timeline_html}</div></section>
<section class="section"><h2 class="section-title">SOAR Response Actions</h2><div class="actions">{action_rows}</div></section>
<section class="section"><h2 class="section-title">Recommended Remediation</h2>{_items(report.get('recommended_actions'),'remediation')}</section>
</div><footer class="footer"><div><strong>SanitialX Professional Reporting</strong><br>AI-generated analysis must be validated by a qualified SOC analyst before external distribution.</div><div style="text-align:right">{_text(report.get('report_id'))}<br>CONFIDENTIAL · SOC USE</div></footer></main></body></html>'''
