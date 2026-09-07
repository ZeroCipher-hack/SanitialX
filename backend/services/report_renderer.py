"""Professional, printable SOC incident report rendering."""
from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from typing import Any


def _text(value: Any) -> str:
    return escape(str(value if value not in (None, "") else "—"))


def _items(values: list[Any] | None) -> str:
    if not values:
        return '<div class="empty">No evidence recorded.</div>'
    rows = []
    for value in values:
        if isinstance(value, dict):
            value = value.get("name") or value.get("technique") or value.get("value") or value
        rows.append(f"<li>{_text(value)}</li>")
    return "<ul>" + "".join(rows) + "</ul>"


def _detail_html(value: Any) -> str:
    if isinstance(value, dict):
        parts = []
        for key, item in value.items():
            if isinstance(item, dict):
                nested = "".join(
                    f'<div class="detail-line"><span class="detail-key">{_text(nested_key)}</span><span>{_text(nested_value)}</span></div>'
                    for nested_key, nested_value in item.items()
                )
                parts.append(
                    f'<div class="detail-group"><div class="detail-key">{_text(key)}</div>{nested}</div>'
                )
            else:
                parts.append(
                    f'<div class="detail-line"><span class="detail-key">{_text(key)}</span><span>{_text(item)}</span></div>'
                )
        return "".join(parts) or '<span class="muted">—</span>'
    return _text(value)


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

    action_rows = "".join(
        f"<tr><td>{_text(a.get('action_type'))}</td><td>{_text(a.get('target_value'))}</td><td>{_text(a.get('status'))}</td><td>{_text(a.get('approved_by') or a.get('rejected_by'))}</td></tr>"
        for a in actions
    ) or '<tr><td colspan="4">No response actions recorded.</td></tr>'

    timeline_html = "".join(
        f"<tr><td class='timeline-time'>{_text(i.get('timestamp'))}</td><td class='timeline-event'>{_text(i.get('event'))}</td><td class='timeline-actor'>{_text(i.get('actor'))}</td><td class='timeline-details'>{_detail_html(i.get('details'))}</td></tr>"
        for i in timeline_rows
    ) or '<tr><td colspan="4">No response timeline events recorded.</td></tr>'

    vuln_rows = "".join(
        f"<tr><td><b>{_text(v.get('cve_id'))}</b><br>{_text(v.get('severity'))} / CVSS {_text(v.get('cvss_score'))}</td><td>{_text(v.get('agent_id'))}<br>{_text(v.get('matched_software'))}</td><td>{_text(v.get('exposure_status'))}<br>Risk {_text(v.get('risk_score'))} / Confidence {_text(v.get('match_confidence'))}</td><td>KEV: {_text(v.get('known_exploited'))}<br>Exploit: {_text(v.get('exploit_available'))}<br>Internet: {_text(v.get('internet_exposed'))}</td><td>{_text(v.get('event_evidence_score'))}<br>{_text(v.get('rationale'))}</td></tr>"
        for v in vulns
    ) or '<tr><td colspan="5">No deterministic CVE exposure is linked to this incident.</td></tr>'

    return f'''<!doctype html><html><head><meta charset="utf-8"><title>{_text(report.get("report_id"))} — SanitialX</title><style>
@page{{size:A4;margin:18mm 16mm 18mm 16mm}}
*{{box-sizing:border-box}}
html,body{{padding:0}}
body{{font-family:Inter,Arial,sans-serif;color:#172033;margin:0;background:#fff;font-size:12px;line-height:1.5}}
.report{{padding-top:6mm}}
header{{border-bottom:3px solid #172033;padding-bottom:16px;margin-bottom:20px;display:flex;justify-content:space-between;gap:24px}}
header>div:last-child{{text-align:right;min-width:185px}}
h1{{font-size:24px;margin:0}}
h2{{font-size:15px;border-bottom:1px solid #d8dee9;padding-bottom:6px;margin:22px 0 10px;break-after:avoid}}
.brand{{font-weight:800;letter-spacing:1px}}
.muted{{color:#667085}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}}
.card{{border:1px solid #d8dee9;border-radius:6px;padding:10px}}
.label{{font-size:9px;text-transform:uppercase;color:#667085}}
.value{{font-size:13px;font-weight:700;overflow-wrap:anywhere}}
.summary{{border-left:4px solid #475467;background:#f8fafc;padding:12px}}
table{{width:100%;border-collapse:collapse;table-layout:fixed}}
th,td{{border:1px solid #d8dee9;padding:7px;text-align:left;vertical-align:top;overflow-wrap:anywhere;word-break:break-word}}
th{{background:#f2f4f7}}
tr{{break-inside:avoid}}
ul{{padding-left:18px}}
.risk{{font-size:26px;font-weight:800}}
.timeline-time{{width:20%;font-size:10px}}
.timeline-event{{width:15%;font-weight:700}}
.timeline-actor{{width:18%}}
.timeline-details{{width:47%;font-size:10px}}
.detail-line{{display:grid;grid-template-columns:minmax(84px,30%) 1fr;gap:8px;margin:0 0 3px}}
.detail-key{{font-weight:700;color:#475467}}
.detail-group{{margin:4px 0;padding-top:4px;border-top:1px dashed #e4e7ec}}
.footer{{margin-top:28px;padding-top:8px;border-top:1px solid #d8dee9;color:#667085;font-size:9px}}
@media screen{{body{{padding:18px}}.report{{max-width:900px;margin:0 auto;padding:18px 0 32px}}}}
</style></head><body><main class="report">
<header><div><div class="brand">SANITIALX SOC</div><h1>Incident Investigation Report</h1><div class="muted">{_text(report.get('report_id'))}</div></div><div><b>Generated</b><br>{_text(generated)}<br><span class="muted">CONFIDENTIAL — SOC USE</span></div></header>
<div class="grid"><div class="card"><div class="label">Severity</div><div class="value">{_text(report.get('severity'))}</div></div><div class="card"><div class="label">Status</div><div class="value">{_text(report.get('status'))}</div></div><div class="card"><div class="label">AI confidence</div><div class="value">{_text(report.get('confidence_score'))}</div></div><div class="card"><div class="label">Risk score</div><div class="risk">{_text(report.get('overall_risk_score'))}</div></div></div>
<h2>Executive Summary</h2><div class="summary">{_text(report.get('executive_summary'))}</div>
<h2>Incident Metadata</h2><table><tr><th>Incident</th><td>{_text(report.get('incident_id'))}</td><th>Title</th><td>{_text(report.get('title'))}</td></tr><tr><th>Created</th><td>{_text(report.get('created_at'))}</td><th>Updated</th><td>{_text(report.get('updated_at'))}</td></tr><tr><th>Source IP</th><td>{_text(report.get('source_ip'))}</td><th>Destination IP</th><td>{_text(report.get('destination_ip'))}</td></tr><tr><th>Classification</th><td colspan="3">{_text(report.get('threat_classification'))}</td></tr></table>
<h2>Key Findings</h2>{_items(report.get('key_findings'))}<h2>Indicators of Compromise</h2>{_items(report.get('indicators_of_compromise'))}<h2>Affected Assets</h2>{_items(report.get('affected_assets'))}<h2>MITRE / Observed Techniques</h2>{_items(report.get('observed_techniques'))}
<h2>Attack Context</h2><table><tr><th>Initial access vector</th><td>{_text(report.get('initial_access_vector'))}</td></tr><tr><th>Honeypot engagement</th><td>{_text(report.get('honeypot_engagement'))}</td></tr><tr><th>Simulated data loss</th><td>{_text(report.get('simulated_data_loss'))}</td></tr><tr><th>Detection IDs</th><td>{_text(', '.join(report.get('triggering_detection_ids') or []))}</td></tr></table>
<h2>Asset / CVE Exposure Evidence</h2><table><thead><tr><th>CVE</th><th>Asset / Software</th><th>Exposure</th><th>Threat Intel</th><th>Event Evidence</th></tr></thead><tbody>{vuln_rows}</tbody></table>
<h2>Response Timeline</h2><table><thead><tr><th>Timestamp</th><th>Event</th><th>Actor</th><th>Details</th></tr></thead><tbody>{timeline_html}</tbody></table>
<h2>SOAR Response Actions</h2><table><thead><tr><th>Action</th><th>Target</th><th>Status</th><th>Decision actor</th></tr></thead><tbody>{action_rows}</tbody></table>
<h2>Recommended Remediation</h2>{_items(report.get('recommended_actions'))}<div class="footer">Generated by SanitialX Professional Reporting. AI-generated analysis should be validated by a qualified SOC analyst before external distribution.</div></main></body></html>'''
