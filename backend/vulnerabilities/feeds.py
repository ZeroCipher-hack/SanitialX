"""Official vulnerability feed clients for NVD CVE 2.0 and CISA KEV."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import httpx

NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _english_description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions") or []
    for item in descriptions:
        if item.get("lang") == "en":
            return str(item.get("value") or "")
    return str(descriptions[0].get("value") or "") if descriptions else ""


def _cvss(cve: dict[str, Any]) -> tuple[float | None, str]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        candidates = metrics.get(key) or []
        if not candidates:
            continue
        data = candidates[0].get("cvssData") or {}
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or candidates[0].get("baseSeverity") or "UNKNOWN"
        return (float(score) if score is not None else None, str(severity).upper())
    return None, "UNKNOWN"


def _affected_products(cve: dict[str, Any]) -> list[dict[str, Any]]:
    products: list[dict[str, Any]] = []
    configurations = cve.get("configurations") or []
    for configuration in configurations:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable", False):
                    continue
                products.append(
                    {
                        "criteria": match.get("criteria"),
                        "version_start_including": match.get("versionStartIncluding"),
                        "version_start_excluding": match.get("versionStartExcluding"),
                        "version_end_including": match.get("versionEndIncluding"),
                        "version_end_excluding": match.get("versionEndExcluding"),
                    }
                )
    return products


def parse_nvd_item(item: dict[str, Any]) -> dict[str, Any]:
    cve = item.get("cve") or {}
    score, severity = _cvss(cve)
    return {
        "cve_id": str(cve.get("id") or "").upper(),
        "summary": _english_description(cve),
        "cvss_score": score,
        "severity": severity,
        "published_at": _parse_datetime(cve.get("published")),
        "modified_at": _parse_datetime(cve.get("lastModified")),
        "affected_products": _affected_products(cve),
        "references": [str(ref.get("url")) for ref in cve.get("references") or [] if ref.get("url")],
        "source": "nvd",
        "raw": item,
    }


class NvdFeedClient:
    def __init__(self, *, api_key: str | None = None, timeout: float = 30.0) -> None:
        self._api_key = api_key
        self._timeout = timeout

    async def fetch_recent(
        self,
        *,
        published_after: datetime,
        published_before: datetime,
        start_index: int = 0,
        results_per_page: int = 2000,
    ) -> dict[str, Any]:
        headers = {"apiKey": self._api_key} if self._api_key else {}
        params = {
            "pubStartDate": published_after.isoformat(),
            "pubEndDate": published_before.isoformat(),
            "startIndex": start_index,
            "resultsPerPage": results_per_page,
        }
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.get(NVD_CVE_API_URL, params=params, headers=headers)
            response.raise_for_status()
            return response.json()


class CisaKevFeedClient:
    def __init__(self, *, timeout: float = 30.0) -> None:
        self._timeout = timeout

    async def fetch_catalog(self) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.get(CISA_KEV_JSON_URL)
            response.raise_for_status()
            return response.json()

    @staticmethod
    def cve_ids(catalog: dict[str, Any]) -> set[str]:
        return {
            str(item.get("cveID")).upper()
            for item in catalog.get("vulnerabilities") or []
            if item.get("cveID")
        }
