"""Seed synthetic demo data for the Exposure / vulnerability vertical.

This populates assets, a small CVE catalog (with CVSS, CISA KEV flags and
representative EPSS scores) and matching software inventory, then runs the
real exposure evaluation so the Exposure view has prioritized data to show
locally — without needing the external NVD/EPSS/CISA feeds reachable.

The EPSS values here are a STATIC representative snapshot for demo purposes.
In a real deployment the vulnerability sync job fills EPSS from the live
FIRST.org feed; this script never claims the numbers are current.

All data is synthetic and scoped to demo asset IDs (``demo-*``). It is
additive/idempotent: re-running refreshes the same demo records.

Usage (from the backend directory, with the stack's env configured):

    PYTHONPATH=. python -m scripts.seed_demo_data --confirm
    PYTHONPATH=. python -m scripts.seed_demo_data --reset   # remove demo data
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from datetime import datetime, timezone

from sqlalchemy import delete

from core.config import get_settings
from db.models.agent import AgentModel
from db.models.honeypot import HoneypotSessionModel
from db.models.vulnerability import AssetVulnerabilityModel
from db.repositories.agent_repository import PostgresAgentRepository
from db.repositories.honeypot_repository import PostgresHoneypotRepository
from db.repositories.vulnerability_repository import PostgresVulnerabilityRepository
from db.session import DatabaseSessionManager
from honeypot.signal import active_service_categories
from vulnerabilities.service import VulnerabilityService

# ── Demo assets ──────────────────────────────────────────────────────────────
ASSETS = [
    {"agent_id": "demo-web-01", "hostname": "prod-web-01", "ip_address": "10.1.1.10",
     "os": "Ubuntu 22.04", "asset_type": "SERVER", "criticality": "HIGH",
     "environment": "PRODUCTION", "internet_exposed": True, "risk_score": 70,
     "owner": "platform-team", "lifecycle_status": "MANAGED"},
    {"agent_id": "demo-db-01", "hostname": "prod-db-01", "ip_address": "10.1.2.20",
     "os": "Debian 12", "asset_type": "SERVER", "criticality": "CRITICAL",
     "environment": "PRODUCTION", "internet_exposed": False, "risk_score": 55,
     "owner": "data-team", "lifecycle_status": "MANAGED"},
    {"agent_id": "demo-win-01", "hostname": "corp-win-01", "ip_address": "10.2.1.30",
     "os": "Windows Server 2019", "asset_type": "SERVER", "criticality": "HIGH",
     "environment": "PRODUCTION", "internet_exposed": True, "risk_score": 60,
     "owner": "it-team", "lifecycle_status": "MANAGED"},
    {"agent_id": "demo-dev-01", "hostname": "dev-laptop-07", "ip_address": "10.3.3.40",
     "os": "Ubuntu 24.04", "asset_type": "WORKSTATION", "criticality": "LOW",
     "environment": "DEVELOPMENT", "internet_exposed": False, "risk_score": 20,
     "owner": "alice", "lifecycle_status": "MANAGED"},
]


def _cpe(vendor: str, product: str, version: str) -> str:
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def _rule(vendor: str, product: str, *, end_excluding: str | None = None,
          start_including: str | None = None, end_including: str | None = None) -> dict:
    return {
        "criteria": f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*",
        "version_start_including": start_including,
        "version_start_excluding": None,
        "version_end_including": end_including,
        "version_end_excluding": end_excluding,
    }


# ── Demo CVE catalog (cvss, severity, KEV, EPSS snapshot, affected rule) ──────
# Note the deliberate contrast: CVE-2023-DEMO-DORMANT has a HIGHER CVSS (9.8)
# than Heartbleed (7.5) but a tiny EPSS, so it ranks BELOW the actively
# exploited ones — exactly what CVSS-only prioritization gets wrong.
VULNS = [
    {"cve_id": "CVE-2021-44228", "summary": "Apache Log4j2 JNDI RCE (Log4Shell).",
     "cvss": 10.0, "severity": "CRITICAL", "kev": True, "epss": (0.94, 0.999),
     "vendor": "apache", "product": "log4j", "rule": _rule("apache", "log4j", start_including="2.0", end_excluding="2.15.0")},
    {"cve_id": "CVE-2022-22965", "summary": "Spring Framework data binding RCE (Spring4Shell).",
     "cvss": 9.8, "severity": "CRITICAL", "kev": True, "epss": (0.95, 0.999),
     "vendor": "vmware", "product": "spring_framework", "rule": _rule("vmware", "spring_framework", end_excluding="5.3.18")},
    {"cve_id": "CVE-2014-0160", "summary": "OpenSSL TLS heartbeat information disclosure (Heartbleed).",
     "cvss": 7.5, "severity": "HIGH", "kev": True, "epss": (0.94, 0.998),
     "vendor": "openssl", "product": "openssl", "rule": _rule("openssl", "openssl", start_including="1.0.1", end_excluding="1.0.1g")},
    {"cve_id": "CVE-2017-0144", "summary": "Windows SMBv1 remote code execution (EternalBlue).",
     "cvss": 8.1, "severity": "HIGH", "kev": True, "epss": (0.95, 0.999),
     "vendor": "microsoft", "product": "smbv1", "rule": _rule("microsoft", "smbv1", end_excluding="2.0")},
    {"cve_id": "CVE-2023-DEMO-DORMANT", "summary": "Synthetic critical-CVSS flaw with no real-world exploitation.",
     "cvss": 9.8, "severity": "CRITICAL", "kev": False, "epss": (0.02, 0.21),
     "vendor": "acme", "product": "widget", "rule": _rule("acme", "widget", end_excluding="3.0.0")},
]

# agent_id -> list of (vendor, product, version) installed
INVENTORY = {
    "demo-web-01": [("apache", "log4j", "2.14.1"), ("vmware", "spring_framework", "5.3.10"), ("acme", "widget", "2.4.0")],
    "demo-db-01": [("openssl", "openssl", "1.0.1f"), ("acme", "widget", "2.4.0")],
    "demo-win-01": [("microsoft", "smbv1", "1.0"), ("apache", "log4j", "2.13.0")],
    "demo-dev-01": [("vmware", "spring_framework", "5.3.10")],
}


async def _reset(mgr: DatabaseSessionManager) -> None:
    async with mgr.sessionmaker() as session:
        demo_ids = [a["agent_id"] for a in ASSETS]
        await session.execute(delete(AssetVulnerabilityModel).where(AssetVulnerabilityModel.agent_id.in_(demo_ids)))
        for aid in demo_ids:
            model = await session.get(AgentModel, aid)
            if model is not None:
                await session.delete(model)
        hp = await session.get(HoneypotSessionModel, "demo-hp-web-01")
        if hp is not None:
            await session.delete(hp)
        await session.commit()
    print("Removed demo assets, exposures and the demo honeypot session (shared CVE catalog left intact).")


async def _seed(mgr: DatabaseSessionManager) -> None:
    async with mgr.sessionmaker() as session:
        agent_repo = PostgresAgentRepository(session)
        vuln_repo = PostgresVulnerabilityRepository(session)
        service = VulnerabilityService(vuln_repo)

        for asset in ASSETS:
            await agent_repo.upsert_agent(asset)
        for aid, packages in INVENTORY.items():
            await vuln_repo.replace_software_inventory(aid, [
                {"vendor": v, "product": p, "version": ver, "cpe": _cpe(v, p, ver)}
                for v, p, ver in packages
            ])

        epss_map: dict[str, tuple[float, float | None]] = {}
        for v in VULNS:
            await vuln_repo.upsert_vulnerability({
                "cve_id": v["cve_id"], "summary": v["summary"], "cvss_score": v["cvss"],
                "severity": v["severity"], "known_exploited": v["kev"],
                "affected_products": [v["rule"]],
            })
            epss_map[v["cve_id"]] = v["epss"]
        await vuln_repo.set_epss_scores(epss_map)

        # A live honeypot hit on a WEB decoy — the local real-time attack signal.
        honeypot_repo = PostgresHoneypotRepository(session)
        await honeypot_repo.add_session({
            "session_id": "demo-hp-web-01",
            "attacker_ip": "203.0.113.66",
            "service": "Fake Web Panel",
            "started_at": datetime.now(timezone.utc),
            "duration_seconds": 42,
            "credentials_attempted": ["admin:admin", "root:toor"],
            "commands_executed": ["GET /admin", "POST /login"],
            "risk_score": 80,
            "notes": "Demo: attacker probing a web decoy.",
        })
        active_threat_services = active_service_categories(
            await honeypot_repo.recent_sessions(within_hours=24), within_hours=24
        )

        total = 0
        for asset in ASSETS:
            exposures = await service.evaluate_agent(
                agent_id=asset["agent_id"], asset_risk_score=asset["risk_score"],
                internet_exposed=asset["internet_exposed"], criticality=asset["criticality"],
                active_threat_services=active_threat_services,
            )
            total += len(exposures)

        rows = await vuln_repo.list_enriched_exposures(limit=100)

    print(f"Seeded {len(ASSETS)} assets, {len(VULNS)} CVEs, {total} exposures.\n")
    print("Prioritized exposures (what the Exposure view shows):")
    print(f"{'#':<3}{'RISK':<9}{'ASSET':<14}{'CVE':<24}{'SEV':<10}{'CVSS':<6}{'EPSS':<8}{'KEV':<5}{'ATTACK':<8}")
    print("-" * 92)
    for i, (exp, vuln) in enumerate(rows, 1):
        epss = f"{(vuln.epss_score or 0) * 100:.1f}%"
        print(f"{i:<3}{str(exp.risk_score) + '/100':<9}{exp.agent_id:<14}{exp.cve_id:<24}"
              f"{vuln.severity:<10}{str(vuln.cvss_score):<6}{epss:<8}{'YES' if vuln.known_exploited else 'no':<5}"
              f"{'LIVE' if exp.active_threat else '-':<8}")
    print("\nNote: EPSS values are a static demo snapshot, not live FIRST.org data.")
    print("ATTACK=LIVE means a honeypot saw a live attack on that service (local signal).")


async def main() -> None:
    parser = argparse.ArgumentParser(description="Seed synthetic demo data for the Exposure vertical.")
    parser.add_argument("--confirm", action="store_true", help="Required to write demo data.")
    parser.add_argument("--reset", action="store_true", help="Remove demo assets/exposures instead of seeding.")
    args = parser.parse_args()

    if not args.confirm and not args.reset:
        print("Refusing to run without --confirm (or --reset). This writes synthetic demo data.", file=sys.stderr)
        sys.exit(2)

    settings = get_settings()
    mgr = DatabaseSessionManager(settings.database_url)
    mgr.init()
    try:
        if args.reset:
            await _reset(mgr)
        else:
            await _seed(mgr)
    finally:
        await mgr.close()


if __name__ == "__main__":
    asyncio.run(main())
