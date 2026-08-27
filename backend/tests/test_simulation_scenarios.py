"""Unit tests for the controlled simulation scenario registry."""

import pytest

from simulation.scenarios import SCENARIOS, get_scenario


def test_default_scenario_is_registered() -> None:
    scenario = get_scenario("web_app_compromise")
    assert scenario.name == "WEB_APP_COMPROMISE"
    assert len(scenario.event_indexes) == 9


def test_scenarios_have_unique_names_and_non_empty_events() -> None:
    assert len(SCENARIOS) == len({scenario.name for scenario in SCENARIOS.values()})
    assert all(scenario.event_indexes for scenario in SCENARIOS.values())


def test_unknown_scenario_has_actionable_error() -> None:
    with pytest.raises(ValueError, match="Supported scenarios"):
        get_scenario("NOT_A_REAL_SCENARIO")
