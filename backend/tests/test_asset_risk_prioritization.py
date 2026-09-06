from vulnerabilities.service import VulnerabilityService


def test_asset_context_increases_vulnerability_priority() -> None:
    baseline = VulnerabilityService.calculate_risk_score(
        cvss_score=7.5,
        known_exploited=False,
        exploit_available=False,
        internet_exposed=False,
        asset_risk_score=0,
        criticality="LOW",
    )
    critical_public = VulnerabilityService.calculate_risk_score(
        cvss_score=7.5,
        known_exploited=False,
        exploit_available=False,
        internet_exposed=True,
        asset_risk_score=0,
        criticality="CRITICAL",
    )

    assert baseline == 45
    assert critical_public == 67
    assert critical_public > baseline


def test_known_exploited_critical_public_asset_caps_at_100() -> None:
    score = VulnerabilityService.calculate_risk_score(
        cvss_score=9.8,
        known_exploited=True,
        exploit_available=True,
        internet_exposed=True,
        asset_risk_score=90,
        criticality="CRITICAL",
    )

    assert score == 100


def test_unknown_criticality_is_neutral() -> None:
    unknown = VulnerabilityService.calculate_risk_score(
        cvss_score=5.0,
        known_exploited=False,
        exploit_available=False,
        internet_exposed=False,
        asset_risk_score=0,
        criticality="UNSET",
    )
    medium = VulnerabilityService.calculate_risk_score(
        cvss_score=5.0,
        known_exploited=False,
        exploit_available=False,
        internet_exposed=False,
        asset_risk_score=0,
        criticality="MEDIUM",
    )

    assert unknown == 30
    assert medium == 34
