"""Enriched exposure join: risk score alongside CVSS/EPSS/KEV in one query."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from db.base import Base
from db.models.agent import AgentModel
from db.repositories.vulnerability_repository import PostgresVulnerabilityRepository


@pytest.fixture
async def session() -> AsyncSession:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        s.add(AgentModel(agent_id="agent-1", hostname="host-1", ip_address="10.0.0.1", os="Linux"))
        await s.commit()
        yield s
    await engine.dispose()


@pytest.mark.asyncio
async def test_list_enriched_exposures_joins_cve_intel(session: AsyncSession) -> None:
    repo = PostgresVulnerabilityRepository(session)
    await repo.upsert_vulnerability(
        {
            "cve_id": "CVE-2026-0001",
            "summary": "High-risk, actively exploited",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "known_exploited": True,
        }
    )
    await repo.upsert_vulnerability(
        {
            "cve_id": "CVE-2026-0002",
            "summary": "Severe but not exploited in the wild",
            "cvss_score": 9.9,
            "severity": "CRITICAL",
        }
    )
    await repo.set_epss_scores(
        {"CVE-2026-0001": (0.95, 0.99), "CVE-2026-0002": (0.01, 0.10)}
    )
    await repo.upsert_exposure(
        {"agent_id": "agent-1", "cve_id": "CVE-2026-0001", "risk_score": 92}
    )
    await repo.upsert_exposure(
        {"agent_id": "agent-1", "cve_id": "CVE-2026-0002", "risk_score": 60}
    )

    rows = await repo.list_enriched_exposures(agent_id="agent-1")

    assert [exp.cve_id for exp, _ in rows] == ["CVE-2026-0001", "CVE-2026-0002"]
    top_exposure, top_vuln = rows[0]
    assert top_exposure.risk_score == 92
    assert top_vuln.epss_score == 0.95
    assert top_vuln.known_exploited is True
    # A CVE with no stored exposure is not returned (inner join semantics).
    assert all(exp.agent_id == "agent-1" for exp, _ in rows)


@pytest.mark.asyncio
async def test_list_enriched_exposures_respects_min_risk(session: AsyncSession) -> None:
    repo = PostgresVulnerabilityRepository(session)
    await repo.upsert_vulnerability({"cve_id": "CVE-2026-0003", "summary": "x", "cvss_score": 5.0})
    await repo.upsert_vulnerability({"cve_id": "CVE-2026-0004", "summary": "y", "cvss_score": 8.0})
    await repo.upsert_exposure({"agent_id": "agent-1", "cve_id": "CVE-2026-0003", "risk_score": 30})
    await repo.upsert_exposure({"agent_id": "agent-1", "cve_id": "CVE-2026-0004", "risk_score": 80})

    rows = await repo.list_enriched_exposures(agent_id="agent-1", min_risk_score=70)

    assert [exp.cve_id for exp, _ in rows] == ["CVE-2026-0004"]


@pytest.mark.asyncio
async def test_evaluate_agent_flags_and_boosts_active_threat(session: AsyncSession) -> None:
    from vulnerabilities.service import VulnerabilityService

    repo = PostgresVulnerabilityRepository(session)
    await repo.upsert_vulnerability({
        "cve_id": "CVE-2021-44228",
        "summary": "Log4Shell",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "affected_products": [{
            "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
            "version_end_excluding": "2.15.0",
        }],
    })
    await repo.replace_software_inventory("agent-1", [
        {"vendor": "apache", "product": "log4j", "version": "2.14.1",
         "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"},
    ])
    svc = VulnerabilityService(repo)

    calm = await svc.evaluate_agent(agent_id="agent-1")
    assert calm and calm[0].active_threat is False
    calm_risk = calm[0].risk_score

    # A honeypot hit on a WEB service (log4j is WEB) marks it an active threat.
    hot = await svc.evaluate_agent(agent_id="agent-1", active_threat_services={"WEB"})
    assert hot and hot[0].active_threat is True
    assert hot[0].risk_score >= calm_risk

    # An unrelated active service (SSH) does not flag a WEB exposure.
    unrelated = await svc.evaluate_agent(agent_id="agent-1", active_threat_services={"SSH"})
    assert unrelated and unrelated[0].active_threat is False


@pytest.mark.asyncio
async def test_remediation_status_set_and_preserved(session: AsyncSession) -> None:
    from vulnerabilities.service import VulnerabilityService

    repo = PostgresVulnerabilityRepository(session)
    await repo.upsert_vulnerability({
        "cve_id": "CVE-2021-44228", "summary": "Log4Shell", "cvss_score": 10.0,
        "severity": "CRITICAL",
        "affected_products": [{"criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                               "version_end_excluding": "2.15.0"}],
    })
    await repo.replace_software_inventory("agent-1", [
        {"vendor": "apache", "product": "log4j", "version": "2.14.1",
         "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"},
    ])
    svc = VulnerabilityService(repo)
    exposures = await svc.evaluate_agent(agent_id="agent-1")
    exp = exposures[0]
    assert exp.remediation_status == "OPEN"  # default

    updated = await repo.set_remediation(exp.id, status="RISK_ACCEPTED", note="accepted by sec lead", actor="analyst-jane")
    assert updated is not None
    assert updated.remediation_status == "RISK_ACCEPTED"
    assert updated.remediation_updated_by == "analyst-jane"
    assert updated.remediation_updated_at is not None

    # Re-evaluating the asset must NOT reset the remediation decision.
    again = await svc.evaluate_agent(agent_id="agent-1")
    assert again[0].remediation_status == "RISK_ACCEPTED"
    assert again[0].remediation_note == "accepted by sec lead"


@pytest.mark.asyncio
async def test_set_remediation_missing_exposure_returns_none(session: AsyncSession) -> None:
    repo = PostgresVulnerabilityRepository(session)
    assert await repo.set_remediation(999999, status="RESOLVED", note="", actor="x") is None
