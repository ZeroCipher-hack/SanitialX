"""Controlled attack simulation service for the SanitialX Cyber Range."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from correlation.enums import Severity
from db.repositories.agent_repository import PostgresAgentRepository
from db.repositories.event_repository import PostgresEventRepository
from db.repositories.honeypot_repository import PostgresHoneypotRepository
from db.repositories.incident_repository import PostgresIncidentRepository
from db.repositories.rule_repository import PostgresDetectionRuleRepository
from db.repositories.simulation_repository import PostgresSimulationRepository
from incidents.enums import IncidentStatus
from incidents.models import Incident
from simulation.scenarios import get_scenario


class AttackSimulatorService:
    """Generate correlated synthetic telemetry without touching real systems."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self.event_repo = PostgresEventRepository(session)
        self.agent_repo = PostgresAgentRepository(session)
        self.honeypot_repo = PostgresHoneypotRepository(session)
        self.simulation_repo = PostgresSimulationRepository(session)
        self.incident_repo = PostgresIncidentRepository(session)
        self.rule_repo = PostgresDetectionRuleRepository(session)

    async def run_scenario(self, scenario_name: str = "WEB_APP_COMPROMISE") -> dict[str, Any]:
        """Run a registered scenario and honor persisted detection-rule state."""
        scenario = get_scenario(scenario_name)
        sim_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc)
        timestamps = [now - timedelta(seconds=180 - i * 20) for i in range(9)]

        attacker_ip = "10.0.0.21"
        target_web_ip = "10.0.0.50"
        target_db_ip = "10.0.0.88"
        honeypot_ip = "10.0.0.99"
        c2_ip = "198.51.100.42"

        await self._upsert_agents(now, target_web_ip, target_db_ip, honeypot_ip)

        events = [
            self._event(
                timestamps[0], "RECONNAISSANCE_PORT_SCAN", "MEDIUM", attacker_ip, target_web_ip,
                "anonymous", "web-prod-frontend-01", "RULE-RCON-01", "T1046",
                "Port scan detected targeting ports 80, 443, 22, 3306, 8080.",
                {"ports_scanned": [80, 443, 22, 3306, 8080], "scanner": "synthetic-nmap"}, sim_id,
            ),
            self._event(
                timestamps[1], "AUTH_FAILED_BRUTE_FORCE", "MEDIUM", attacker_ip, target_web_ip,
                "admin", "web-prod-frontend-01", "RULE-AUTH-01", "T1110.001",
                "Multiple failed authentication attempts on HTTP POST /login (14 failures in 30s).",
                {"failed_attempts": 14, "target_uri": "/api/v1/auth/login"}, sim_id,
            ),
            self._event(
                timestamps[2], "AUTH_SUCCESSFUL_COMPROMISE", "HIGH", attacker_ip, target_web_ip,
                "sysadmin_backup", "web-prod-frontend-01", "RULE-AUTH-02", "T1078.003",
                "Successful login for synthetic account sysadmin_backup following brute force series.",
                {"session_token": "SIMULATED_SESSION_TOKEN"}, sim_id,
            ),
            self._event(
                timestamps[3], "COMMAND_INJECTION_DETECTED", "CRITICAL", attacker_ip, target_web_ip,
                "www-data", "web-prod-frontend-01", "RULE-EXPLOIT-01", "T1059.004",
                "Synthetic command-injection payload detected in an HTTP request.",
                {"payload": "SIMULATED_COMMAND_INJECTION"}, sim_id,
            ),
            self._event(
                timestamps[4], "SSH_SESSION_ESTABLISHED", "HIGH", attacker_ip, target_web_ip,
                "sysadmin_backup", "web-prod-frontend-01", "RULE-NET-01", "T1021.004",
                "Synthetic interactive SSH session opened using a simulated stolen key.",
                {"ssh_key_fingerprint": "SIMULATED_FINGERPRINT"}, sim_id,
            ),
            self._event(
                timestamps[5], "HONEYPOT_DECEIVE_INTERACTION", "CRITICAL", attacker_ip, honeypot_ip,
                "root", "decoy-ssh-vault", "RULE-DECEP-01", "T1087.002",
                "Synthetic attacker interaction with the SSH deception node and decoy credential file.",
                {"honeypot_id": "SSH-VAULT-01", "decoy_file": "/var/www/.env.honeypot"}, sim_id,
            ),
            self._event(
                timestamps[6], "PRIVILEGE_ESCALATION_SUID", "CRITICAL", attacker_ip, target_web_ip,
                "root", "web-prod-frontend-01", "RULE-PRIV-01", "T1548.001",
                "Synthetic privilege escalation to root through a vulnerable SUID helper.",
                {"binary": "/usr/local/bin/binary_helper", "effective_uid": 0}, sim_id,
            ),
            self._event(
                timestamps[7], "DATABASE_SENSITIVE_READ", "CRITICAL", target_web_ip, target_db_ip,
                "db_master_admin", "db-internal-cluster-01", "RULE-DATA-01", "T1005",
                "Synthetic SQL read of protected customer data from the simulated database.",
                {"tables": ["customer_records", "payment_vault"], "rows_returned": 24500}, sim_id,
            ),
            self._event(
                timestamps[8], "OUTBOUND_EXFILTRATION_DETECTED", "CRITICAL", target_web_ip, c2_ip,
                "root", "web-prod-frontend-01", "RULE-EXFIL-01", "T1041",
                "Synthetic encrypted outbound transfer of simulated data to a documentation-only C2 address.",
                {"bytes_sent": 50541280, "c2_ip": c2_ip, "port": 8443}, sim_id,
            ),
        ]

        selected = [events[i] for i in scenario.event_indexes]
        emitted: list[dict[str, Any]] = []
        disabled_rules: list[str] = []

        for event in selected:
            rule = await self.rule_repo.get_rule(event["rule_id"])
            if rule is not None and not rule["enabled"]:
                disabled_rules.append(event["rule_id"])
                continue
            if rule is not None and rule.get("severity"):
                event["severity"] = rule["severity"]
            event["details"] = f"[{scenario.name}] {event['details']}"
            await self.event_repo.add_event(event)
            emitted.append(event)

        if any(e["event_type"] == "HONEYPOT_DECEIVE_INTERACTION" for e in emitted):
            await self.honeypot_repo.add_session({
                "session_id": f"HONEY-{uuid.uuid4().hex[:6].upper()}",
                "attacker_ip": attacker_ip,
                "service": "SSH Honeypot & Fake Vault",
                "started_at": timestamps[5],
                "ended_at": timestamps[8],
                "duration_seconds": 134,
                "credentials_attempted": ["admin", "root", "sysadmin_backup", "postgres"],
                "commands_executed": ["whoami", "uname -a", "cat /var/www/.env.honeypot"],
                "files_accessed": ["/var/www/.env.honeypot", "/root/decoy_keys.pem"],
                "risk_score": 95,
                "notes": f"Simulation {sim_id}: attacker trapped in isolated deception node.",
            })

        triggering_ids = list(dict.fromkeys(e["rule_id"] for e in emitted if e["severity"] in {"HIGH", "CRITICAL"}))
        incident_id: str | None = None
        graph_nodes, graph_edges = self._build_graph(emitted)

        if triggering_ids:
            incident_id = f"INC-{now.year}-{uuid.uuid4().hex[:4].upper()}"
            incident_severity = max(
                (Severity(e["severity"]) for e in emitted),
                key=lambda value: {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}[value],
            )
            incident = Incident(
                incident_id=incident_id,
                title=scenario.title,
                description=scenario.description,
                severity=incident_severity,
                status=IncidentStatus.OPEN,
                version=1,
                created_at=now,
                updated_at=now,
                source_ip=attacker_ip,
                destination_ip=target_web_ip,
                triggering_detection_ids=triggering_ids,
                context={
                    "simulation_id": sim_id,
                    "scenario": scenario.name,
                    "overall_risk_score": 96 if incident_severity == Severity.CRITICAL else 78,
                    "disabled_rules": disabled_rules,
                    "simulated_data_loss": "24,500 customer records" if any(e["event_type"] == "DATABASE_SENSITIVE_READ" for e in emitted) else "None",
                    "graph_nodes": graph_nodes,
                    "graph_edges": graph_edges,
                    "observed_techniques": list(dict.fromkeys(e["mitre_technique"] for e in emitted)),
                },
            )
            created_inc = await self.incident_repo.create(incident)
            incident_id = created_inc.incident_id

        sim_model = await self.simulation_repo.add_simulation({
            "simulation_id": sim_id,
            "scenario_name": scenario.name,
            "target_environment": "SanitialX Cyber Range",
            "difficulty": scenario.difficulty,
            "status": "COMPLETED",
            "started_at": timestamps[0],
            "completed_at": now,
            "generated_incident_id": incident_id,
            "events_generated": len(emitted),
            "details": {
                "attacker_ip": attacker_ip,
                "victim_ip": target_web_ip,
                "events_requested": len(selected),
                "events_emitted": len(emitted),
                "disabled_rules": disabled_rules,
                "incident_created": incident_id is not None,
                "rule_engine_applied": True,
            },
        })
        return sim_model.to_dict()

    async def _upsert_agents(self, now: datetime, web_ip: str, db_ip: str, honeypot_ip: str) -> None:
        agents = [
            ("agent-web-01", "web-prod-frontend-01", web_ip, "Ubuntu 22.04 LTS (Linux)", "COMPROMISED", 78.4, 64.2, 92, 142),
            ("agent-db-01", "db-internal-cluster-01", db_ip, "Debian 12 Bookworm (Linux)", "WARNING", 42.1, 55.0, 68, 89),
            ("agent-honeypot-01", "decoy-ssh-vault", honeypot_ip, "Alpine Linux (Deception Node)", "ONLINE", 12.0, 22.5, 85, 34),
        ]
        for agent_id, hostname, ip, os_name, status, cpu, memory, risk, count in agents:
            await self.agent_repo.upsert_agent({
                "agent_id": agent_id,
                "hostname": hostname,
                "ip_address": ip,
                "os": os_name,
                "status": status,
                "last_seen": now,
                "cpu_usage": cpu,
                "memory_usage": memory,
                "risk_score": risk,
                "events_count": count,
            })

    @staticmethod
    def _event(
        timestamp: datetime, event_type: str, severity: str, source_ip: str, destination_ip: str,
        user: str, host: str, rule_id: str, mitre: str, details: str,
        raw_payload: dict[str, Any], simulation_id: str,
    ) -> dict[str, Any]:
        return {
            "event_id": f"EVT-{uuid.uuid4().hex[:8].upper()}",
            "timestamp": timestamp,
            "event_type": event_type,
            "severity": severity,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "user": user,
            "host": host,
            "rule_id": rule_id,
            "mitre_technique": mitre,
            "details": details,
            "raw_payload": {**raw_payload, "simulation_id": simulation_id},
        }

    @staticmethod
    def _build_graph(events: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        seen: dict[str, str] = {}
        for index, event in enumerate(events, start=1):
            for ip, node_type in ((event["source_ip"], "source"), (event["destination_ip"], "asset")):
                if not ip or ip in seen:
                    continue
                node_id = f"node-{len(nodes) + 1}"
                seen[ip] = node_id
                nodes.append({
                    "id": node_id,
                    "label": ip,
                    "type": "attacker" if ip.startswith("10.0.0.21") else node_type,
                    "status": "active" if node_type == "source" else "affected",
                    "timestamp": event["timestamp"].isoformat(),
                    "details": event["event_type"],
                })
            source_id = seen.get(event["source_ip"])
            target_id = seen.get(event["destination_ip"])
            if source_id and target_id:
                edges.append({"source": source_id, "target": target_id, "label": event["mitre_technique"]})
        return nodes, edges
