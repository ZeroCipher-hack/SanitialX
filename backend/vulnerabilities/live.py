"""Live-event vulnerability correlation hook for the background worker."""

from __future__ import annotations

from db.repositories.agent_repository import PostgresAgentRepository
from db.repositories.vulnerability_repository import PostgresVulnerabilityRepository
from vulnerabilities.correlation import VulnerabilityEventCorrelator


class LiveVulnerabilityCorrelationHook:
    """Correlate each new normalized event with existing asset exposures.

    This hook is intentionally optional: failure here must not break the core
    detection/correlation worker. The worker owns error isolation.
    """

    def __init__(self, session_factory) -> None:
        self._session_factory = session_factory

    async def __call__(self, event) -> int:
        async with self._session_factory() as session:
            agents = PostgresAgentRepository(session)
            vulnerabilities = PostgresVulnerabilityRepository(session)

            # Prefer destination asset; fall back to source for endpoint-originated events.
            agent = await agents.get_agent_by_ip(getattr(event, "destination_ip", None))
            if agent is None:
                agent = await agents.get_agent_by_ip(getattr(event, "source_ip", None))
            if agent is None:
                return 0

            exposures = await vulnerabilities.list_asset_exposures(
                agent_id=agent["agent_id"],
                min_risk_score=70,
                limit=500,
                offset=0,
            )
            if not exposures:
                return 0

            correlator = VulnerabilityEventCorrelator(session)
            incidents_created = 0
            for exposure in exposures:
                vulnerability = await vulnerabilities.get_vulnerability(exposure.cve_id)
                if vulnerability is None:
                    continue
                result = await correlator.correlate_live_event(
                    event=event,
                    exposure=exposure,
                    vulnerability=vulnerability,
                    agent=agent,
                    create_incident=True,
                )
                if result["incident_created"]:
                    incidents_created += 1
            return incidents_created
