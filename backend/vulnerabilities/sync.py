"""Synchronization orchestration for NVD CVE and CISA KEV feeds."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from db.repositories.vulnerability_repository import PostgresVulnerabilityRepository
from vulnerabilities.feeds import CisaKevFeedClient, NvdFeedClient, parse_nvd_item


class VulnerabilitySyncService:
    def __init__(
        self,
        repository: PostgresVulnerabilityRepository,
        *,
        nvd_client: NvdFeedClient | None = None,
        kev_client: CisaKevFeedClient | None = None,
    ) -> None:
        self._repository = repository
        self._nvd = nvd_client or NvdFeedClient()
        self._kev = kev_client or CisaKevFeedClient()

    async def sync_recent(
        self,
        *,
        hours: int = 24,
        results_per_page: int = 2000,
        max_pages: int = 10,
    ) -> dict[str, Any]:
        """Fetch recent NVD CVEs, persist them, then enrich with CISA KEV."""
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=max(1, min(hours, 24 * 30)))

        ingested = 0
        start_index = 0
        pages = 0
        total_results = 0

        while pages < max_pages:
            payload = await self._nvd.fetch_recent(
                published_after=start,
                published_before=now,
                start_index=start_index,
                results_per_page=results_per_page,
            )
            items = payload.get("vulnerabilities") or []
            total_results = int(payload.get("totalResults") or len(items))

            for item in items:
                parsed = parse_nvd_item(item)
                if not parsed.get("cve_id"):
                    continue
                await self._repository.upsert_vulnerability(parsed)
                ingested += 1

            pages += 1
            returned = len(items)
            start_index += returned
            if returned == 0 or start_index >= total_results:
                break

        kev_catalog = await self._kev.fetch_catalog()
        kev_ids = self._kev.cve_ids(kev_catalog)
        marked_kev = await self._repository.mark_known_exploited(kev_ids)

        return {
            "window_start": start,
            "window_end": now,
            "nvd_pages": pages,
            "nvd_total_results": total_results,
            "nvd_records_processed": ingested,
            "kev_catalog_size": len(kev_ids),
            "stored_records_marked_known_exploited": marked_kev,
        }
