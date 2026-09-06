"""Critical vulnerability exposure alert generation."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models.vulnerability import AssetVulnerabilityModel, VulnerabilityModel
from db.models.vulnerability_alert import VulnerabilityAlertModel


class VulnerabilityAlertService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def generate_critical_alerts(self, *, min_risk_score: int = 80) -> int:
        stmt = (
            select(AssetVulnerabilityModel, VulnerabilityModel)
            .join(VulnerabilityModel, VulnerabilityModel.cve_id == AssetVulnerabilityModel.cve_id)
            .where(AssetVulnerabilityModel.risk_score >= min_risk_score)
        )
        rows = (await self._session.execute(stmt)).all()
        created = 0
        now = datetime.now(timezone.utc)

        for exposure, vulnerability in rows:
            result = await self._session.execute(
                select(VulnerabilityAlertModel).where(
                    VulnerabilityAlertModel.agent_id == exposure.agent_id,
                    VulnerabilityAlertModel.cve_id == exposure.cve_id,
                    VulnerabilityAlertModel.alert_type == "CRITICAL_EXPOSURE",
                )
            )
            alert = result.scalar_one_or_none()
            title = f"Critical vulnerability exposure: {exposure.cve_id}"
            message = (
                f"Asset {exposure.agent_id} has risk {exposure.risk_score}/100 for {exposure.cve_id}. "
                f"Status={exposure.status}; confidence={round(exposure.match_confidence * 100)}%; "
                f"known_exploited={'yes' if vulnerability.known_exploited else 'no'}; "
                f"internet_exposed={'yes' if exposure.internet_exposed else 'no'}."
            )
            severity = "CRITICAL" if exposure.risk_score >= 90 or vulnerability.known_exploited else "HIGH"

            if alert is None:
                alert = VulnerabilityAlertModel(
                    agent_id=exposure.agent_id,
                    cve_id=exposure.cve_id,
                    alert_type="CRITICAL_EXPOSURE",
                    severity=severity,
                    title=title,
                    message=message,
                    risk_score=exposure.risk_score,
                    acknowledged=False,
                    created_at=now,
                    updated_at=now,
                )
                self._session.add(alert)
                created += 1
            else:
                alert.severity = severity
                alert.title = title
                alert.message = message
                alert.risk_score = exposure.risk_score
                alert.updated_at = now

        await self._session.commit()
        return created

    async def list_alerts(self, *, unacknowledged_only: bool = False, limit: int = 100):
        stmt = select(VulnerabilityAlertModel)
        if unacknowledged_only:
            stmt = stmt.where(VulnerabilityAlertModel.acknowledged.is_(False))
        stmt = stmt.order_by(desc(VulnerabilityAlertModel.risk_score), desc(VulnerabilityAlertModel.created_at)).limit(limit)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def acknowledge(self, alert_id: int) -> VulnerabilityAlertModel | None:
        alert = await self._session.get(VulnerabilityAlertModel, alert_id)
        if alert is None:
            return None
        alert.acknowledged = True
        alert.updated_at = datetime.now(timezone.utc)
        await self._session.commit()
        await self._session.refresh(alert)
        return alert
