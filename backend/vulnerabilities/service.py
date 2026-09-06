"""Business logic for vulnerability intelligence."""

from __future__ import annotations

from datetime import datetime, timezone

from db.models.vulnerability import AssetVulnerabilityModel, VulnerabilityModel
from db.repositories.vulnerability_repository import PostgresVulnerabilityRepository
from vulnerabilities.matcher import match_software_to_rule


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

    async def evaluate_agent(
        self,
        *,
        agent_id: str,
        asset_risk_score: int = 0,
        internet_exposed: bool = False,
    ) -> list[AssetVulnerabilityModel]:
        """Match an agent's inventory against stored affected CPE/version rules."""
        inventory = await self._repository.list_software_inventory(agent_id)
        vulnerabilities = await self._repository.list_all_vulnerabilities()
        exposures: list[AssetVulnerabilityModel] = []

        for vuln in vulnerabilities:
            best_match: tuple[float, object, str] | None = None
            for software in inventory:
                for rule in vuln.affected_products or []:
                    matched, confidence, rationale = match_software_to_rule(
                        vendor=software.vendor,
                        product=software.product,
                        version=software.version,
                        rule=rule,
                    )
                    if not matched:
                        continue
                    if best_match is None or confidence > best_match[0]:
                        best_match = (confidence, software, rationale)

            if best_match is None:
                continue

            confidence, software, rationale = best_match
            risk_score = self.calculate_risk_score(
                cvss_score=vuln.cvss_score,
                known_exploited=vuln.known_exploited,
                exploit_available=vuln.exploit_available,
                internet_exposed=internet_exposed,
                asset_risk_score=asset_risk_score,
            )
            exposure = await self._repository.upsert_exposure(
                {
                    "agent_id": agent_id,
                    "cve_id": vuln.cve_id,
                    "status": "AFFECTED" if confidence >= 0.95 else "POTENTIALLY_AFFECTED",
                    "match_confidence": confidence,
                    "risk_score": risk_score,
                    "internet_exposed": internet_exposed,
                    "matched_software": {
                        "vendor": software.vendor,
                        "product": software.product,
                        "version": software.version,
                        "package_name": software.package_name,
                    },
                    "rationale": rationale,
                    "last_evaluated": datetime.now(timezone.utc),
                }
            )
            exposures.append(exposure)

        return sorted(exposures, key=lambda item: item.risk_score, reverse=True)

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
