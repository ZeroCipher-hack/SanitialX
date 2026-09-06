"""Business logic for vulnerability intelligence."""

from __future__ import annotations

from db.models.vulnerability import AssetVulnerabilityModel, VulnerabilityModel
from db.repositories.vulnerability_repository import PostgresVulnerabilityRepository


class VulnerabilityService:
    def __init__(self, repository: PostgresVulnerabilityRepository) -> None:
        self._repository = repository

    async def list_vulnerabilities(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        severity: str | None = None,
        known_exploited: bool | None = None,
    ) -> list[VulnerabilityModel]:
        return await self._repository.list_vulnerabilities(
            limit=limit,
            offset=offset,
            severity=severity,
            known_exploited=known_exploited,
        )

    async def get_vulnerability(self, cve_id: str) -> VulnerabilityModel | None:
        return await self._repository.get_vulnerability(cve_id)

    async def list_exposures(
        self,
        *,
        agent_id: str | None = None,
        min_risk_score: int | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AssetVulnerabilityModel]:
        return await self._repository.list_asset_exposures(
            agent_id=agent_id,
            min_risk_score=min_risk_score,
            limit=limit,
            offset=offset,
        )

    @staticmethod
    def calculate_risk_score(
        *,
        cvss_score: float | None,
        known_exploited: bool,
        exploit_available: bool,
        internet_exposed: bool,
        asset_risk_score: int = 0,
    ) -> int:
        """Return a 0-100 prioritization score for an affected asset.

        This is intentionally deterministic so analysts can explain why an
        exposure was prioritized. It is not a replacement for CVSS.
        """
        score = int((cvss_score or 0.0) * 6)
        if known_exploited:
            score += 20
        if exploit_available:
            score += 10
        if internet_exposed:
            score += 10
        score += min(max(asset_risk_score, 0), 100) // 10
        return min(score, 100)
