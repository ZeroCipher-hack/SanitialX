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
        overlap_minutes: int = 5,
    ) -> dict[str, Any]:
        """Incrementally sync NVD and enrich with CISA KEV.

        The last successful NVD window end is persisted. A small overlap is
        intentionally re-read so records arriving near a window boundary are
        not missed; CVE upserts make that overlap idempotent.
        """
        now = datetime.now(timezone.utc)
        state = await self._repository.get_sync_state("nvd")
        fallback_start = now - timedelta(hours=max(1, min(hours, 24 * 30)))
        if state and state.last_success_at:
            start = state.last_success_at - timedelta(minutes=max(0, overlap_minutes))
        else:
            start = fallback_start

        await self._repository.upsert_sync_state(
            feed="nvd",
            last_attempt_at=now,
            last_error=None,
        )

        ingested = 0
        start_index = 0
        pages = 0
        total_results = 0

        try:
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

            await self._repository.upsert_sync_state(
                feed="nvd",
                last_attempt_at=now,
                last_success_at=now,
                last_error=None,
                records_processed=ingested,
            )
            await self._repository.upsert_sync_state(
                feed="cisa_kev",
                last_attempt_at=now,
                last_success_at=now,
                last_error=None,
                records_processed=len(kev_ids),
            )
        except Exception as exc:
            await self._repository.upsert_sync_state(
                feed="nvd",
                last_attempt_at=now,
                last_error=f"{type(exc).__name__}: {exc}",
                records_processed=ingested,
            )
            raise

        return {
            "window_start": start,
            "window_end": now,
            "incremental": bool(state and state.last_success_at),
            "overlap_minutes": max(0, overlap_minutes),
            "nvd_pages": pages,
            "nvd_total_results": total_results,
            "nvd_records_processed": ingested,
            "kev_catalog_size": len(kev_ids),
            "stored_records_marked_known_exploited": marked_kev,
            "last_success_at": now,
        }
