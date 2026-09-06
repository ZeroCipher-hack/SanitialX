from services.report_renderer import render_incident_report


def test_professional_report_contains_core_soc_sections_and_escapes_input():
    report={"report_id":"REP-1","incident_id":"inc-1","title":"<script>alert(1)</script>","severity":"HIGH","status":"OPEN","created_at":"2026-09-06T10:00:00Z","updated_at":"2026-09-06T10:01:00Z","source_ip":"10.0.0.1","destination_ip":"10.0.0.2","triggering_detection_ids":["det-1"],"executive_summary":"Suspicious activity detected.","threat_classification":"Credential Access","confidence_score":91,"key_findings":["Repeated authentication failures"],"indicators_of_compromise":["10.0.0.1"],"initial_access_vector":"SSH","affected_assets":["srv-01"],"observed_techniques":["T1110"],"honeypot_engagement":False,"simulated_data_loss":False,"overall_risk_score":82,"recommended_actions":["Rotate credentials"]}
    html=render_incident_report(report,soar_actions=[{"action_type":"COLLECT_FORENSICS","target_value":"srv-01","status":"EXECUTED","approved_by":"analyst","rejected_by":None}],timeline=[{"timestamp":"2026-09-06T10:02:00Z","event":"APPROVED","actor":"analyst","details":{"note":"validated"}}],vulnerability_evidence=[{"cve_id":"CVE-2026-1234","agent_id":"srv-01","severity":"CRITICAL","cvss_score":9.8,"known_exploited":True,"exploit_available":True,"exposure_status":"AFFECTED","risk_score":95,"match_confidence":0.99,"internet_exposed":True,"matched_software":{"product":"demo","version":"1.0"},"rationale":"version matched","event_evidence_score":90}])
    for text in ("Incident Investigation Report","Executive Summary","Indicators of Compromise","MITRE / Observed Techniques","Asset / CVE Exposure Evidence","CVE-2026-1234","Response Timeline","SOAR Response Actions","Recommended Remediation","COLLECT_FORENSICS","APPROVED","analyst"):assert text in html
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_professional_report_handles_empty_evidence():
    html=render_incident_report({"report_id":"REP-2","incident_id":"inc-2","title":"Test"})
    assert "No evidence recorded." in html
    assert "No response actions recorded." in html
    assert "No response timeline events recorded." in html
    assert "No deterministic CVE exposure is linked to this incident." in html
