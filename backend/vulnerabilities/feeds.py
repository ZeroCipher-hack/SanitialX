"""Official vulnerability feed clients for NVD CVE 2.0 and CISA KEV."""

from __future__ import annotations

import asyncio
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _retry_delay(response: httpx.Response | None, attempt: int, base_delay: float) -> float:
    if response is not None:
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                return max(0.0, float(retry_after))
            except ValueError:
                try:
                    retry_at = parsedate_to_datetime(retry_after)
                    now = datetime.now(retry_at.tzinfo)
                    return max(0.0, (retry_at - now).total_seconds())
                except (TypeError, ValueError, OverflowError):
                    pass
    return min(base_delay * (2 ** attempt), 60.0)


async def _get_json_with_retry(
    url: str,
    *,
    timeout: float,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    max_retries: int = 4,
    base_delay: float = 1.0,
) -> dict[str, Any]:
    last_error: Exception | None = None
    async with httpx.AsyncClient(timeout=timeout) as client:
        for attempt in range(max_retries + 1):
            response: httpx.Response | None = None
            try:
                response = await client.get(url, params=params, headers=headers)
                if response.status_code not in _RETRYABLE_STATUS:
                    response.raise_for_status()
                    return response.json()
                last_error = httpx.HTTPStatusError(
                    f"retryable HTTP {response.status_code}",
                    request=response.request,
                    response=response,
                )
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                last_error = exc

            if attempt >= max_retries:
                break
            await asyncio.sleep(_retry_delay(response, attempt, base_delay))

    assert last_error is not None
    raise last_error


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
    for configuration in cve.get("configurations") or []:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable", False):
                    continue
                products.append({
                    "criteria": match.get("criteria"),
                    "version_start_including": match.get("versionStartIncluding"),
                    "version_start_excluding": match.get("versionStartExcluding"),
                    "version_end_including": match.get("versionEndIncluding"),
                    "version_end_excluding": match.get("versionEndExcluding"),
                })
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

    async def fetch_recent(self, *, published_after: datetime, published_before: datetime, start_index: int = 0, results_per_page: int = 2000) -> dict[str, Any]:
        headers = {"apiKey": self._api_key} if self._api_key else {}
        params = {
            "pubStartDate": published_after.isoformat(),
            "pubEndDate": published_before.isoformat(),
            "startIndex": start_index,
            "resultsPerPage": results_per_page,
        }
        return await _get_json_with_retry(
            NVD_CVE_API_URL,
            timeout=self._timeout,
            params=params,
            headers=headers,
        )


class CisaKevFeedClient:
    def __init__(self, *, timeout: float = 30.0) -> None:
        self._timeout = timeout

    async def fetch_catalog(self) -> dict[str, Any]:
        return await _get_json_with_retry(CISA_KEV_JSON_URL, timeout=self._timeout)

    @staticmethod
    def cve_ids(catalog: dict[str, Any]) -> set[str]:
        return {
            str(item.get("cveID")).upper()
            for item in catalog.get("vulnerabilities") or []
            if item.get("cveID")
        }
