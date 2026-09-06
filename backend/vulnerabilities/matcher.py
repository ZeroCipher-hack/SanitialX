"""Deterministic package/CPE/product/version matching helpers."""

from __future__ import annotations

import re
from typing import Any


def _version_key(value: str) -> tuple:
    parts = re.split(r"([0-9]+)", (value or "").strip().lower())
    key: list[tuple[int, Any]] = []
    for part in parts:
        if not part:
            continue
        if part.isdigit():
            key.append((0, int(part)))
        else:
            key.append((1, part))
    return tuple(key)


def _in_range(version: str, rule: dict[str, Any]) -> bool:
    current = _version_key(version)
    start_inc = rule.get("version_start_including")
    start_exc = rule.get("version_start_excluding")
    end_inc = rule.get("version_end_including")
    end_exc = rule.get("version_end_excluding")

    if start_inc and current < _version_key(str(start_inc)):
        return False
    if start_exc and current <= _version_key(str(start_exc)):
        return False
    if end_inc and current > _version_key(str(end_inc)):
        return False
    if end_exc and current >= _version_key(str(end_exc)):
        return False
    return True


def parse_cpe(criteria: str | None) -> tuple[str, str, str] | None:
    """Return vendor, product, version from a CPE 2.3 string when possible."""
    if not criteria or not criteria.startswith("cpe:2.3:"):
        return None
    parts = criteria.split(":")
    if len(parts) < 6:
        return None
    return (
        parts[3].replace("\\", "").lower(),
        parts[4].replace("\\", "").lower(),
        parts[5].replace("\\", "").lower(),
    )


def _normalize_purl(value: str | None) -> str | None:
    normalized = (value or "").strip().lower()
    return normalized or None


def match_software_to_rule(
    *,
    vendor: str,
    product: str,
    version: str,
    rule: dict[str, Any],
    cpe: str | None = None,
    purl: str | None = None,
    ecosystem: str | None = None,
    package_name: str | None = None,
) -> tuple[bool, float, str]:
    """Match one observed package to an affected-product rule.

    Identity precedence is deliberate:
    1. exact PURL when the vulnerability rule provides one;
    2. observed CPE identity when available;
    3. legacy vendor/product/version fields.

    This keeps NVD CPE compatibility while allowing richer package feeds later.
    """
    rule_purl = _normalize_purl(rule.get("purl"))
    software_purl = _normalize_purl(purl)
    if rule_purl:
        if not software_purl or software_purl != rule_purl:
            return False, 0.0, "purl mismatch"
        if not _in_range(version, rule):
            return False, 0.0, "version outside affected range"
        return True, 1.0, "software matches affected PURL/version rule"

    parsed_rule = parse_cpe(rule.get("criteria"))
    if parsed_rule is None:
        return False, 0.0, "invalid or unsupported affected-product identity"

    cpe_vendor, cpe_product, cpe_version = parsed_rule
    observed_cpe = parse_cpe(cpe)
    if cpe and observed_cpe is None:
        return False, 0.0, "invalid observed CPE"

    if observed_cpe is not None:
        observed_vendor, observed_product, observed_version = observed_cpe
        if observed_product != cpe_product:
            return False, 0.0, "CPE product mismatch"
        if observed_vendor != cpe_vendor:
            return False, 0.0, "CPE vendor mismatch"
        effective_version = version.strip().lower() or observed_version
        if cpe_version not in {"*", "-"} and observed_version not in {"*", "-", cpe_version}:
            return False, 0.0, "CPE version mismatch"
        if not _in_range(effective_version, rule):
            return False, 0.0, "version outside affected range"
        confidence = 1.0 if cpe_version not in {"*", "-"} else 0.99
        return True, confidence, "observed CPE matches affected CPE/version rule"

    vendor_norm = (vendor or "").strip().lower()
    product_norm = (product or "").strip().lower()
    version_norm = (version or "").strip().lower()

    vendor_matches = not vendor_norm or vendor_norm == cpe_vendor
    product_matches = product_norm == cpe_product
    if not product_matches:
        return False, 0.0, "product mismatch"
    if not vendor_matches:
        return False, 0.0, "vendor mismatch"

    if cpe_version not in {"*", "-"} and version_norm != cpe_version:
        return False, 0.0, "version mismatch"
    if not _in_range(version_norm, rule):
        return False, 0.0, "version outside affected range"

    confidence = 0.95 if vendor_norm else 0.85
    if cpe_version not in {"*", "-"}:
        confidence = min(1.0, confidence + 0.05)
    return True, confidence, "software matches affected CPE/version rule"
