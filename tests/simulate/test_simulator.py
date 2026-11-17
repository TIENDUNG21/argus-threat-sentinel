from datetime import UTC, datetime
from functools import cache
from pathlib import Path

import pytest

from argus.ingest.combined import parse_combined
from argus.ingest.reader import read_events
from argus.pipeline import ScanOptions, scan
from argus.rules.loader import builtin_rules
from argus.simulate import Labels, Simulation, simulate, write_simulation
from argus.simulate.render import escape_field, render_web
from argus.simulate.world import WebHit


@cache
def small(seed: int) -> Simulation:
    return simulate(seed, visitors_per_day=40)


def test_same_seed_gives_identical_output() -> None:
    first = simulate(5, visitors_per_day=30)
    second = simulate(5, visitors_per_day=30)
    assert first.access_lines == second.access_lines
    assert first.auth_lines == second.auth_lines
    assert first.labels.to_json() == second.labels.to_json()


def test_different_seeds_differ() -> None:
    assert small(1).access_lines != small(2).access_lines


def test_lines_are_time_ordered_apart_from_injected_garbage(tmp_path: Path) -> None:
    files = write_simulation(small(1), tmp_path)
    events, _ = read_events(files["access.log"])
    stamps = [event.ts for event in events]
    assert stamps == sorted(stamps)


def test_scan_counts_exactly_the_injected_malformed_lines(tmp_path: Path) -> None:
    sim = small(2)
    files = write_simulation(sim, tmp_path)
    result = scan([files["access.log"], files["auth.log"]], ScanOptions(ml=False))
    assert result.stats.errors == []
    assert result.stats.malformed == sum(sim.labels.malformed.values())
    assert sim.labels.malformed["access.log"] >= 1
    by_file = {summary.path: summary.malformed for summary in result.inputs}
    assert by_file[str(files["access.log"])] == sim.labels.malformed["access.log"]
    assert by_file[str(files["auth.log"])] == sim.labels.malformed["auth.log"]


def test_every_actor_in_the_logs_is_labelled(tmp_path: Path) -> None:
    sim = small(3)
    files = write_simulation(sim, tmp_path)
    for name in ("access.log", "auth.log"):
        events, _ = read_events(files[name])
        assert {event.ip for event in events} <= set(sim.labels.actors)


def test_labels_cover_every_builtin_rule_and_both_classes() -> None:
    expected = {
        rule
        for seed in (1, 2, 3)
        for label in small(seed).labels.actors.values()
        for rule in label.expected
    }
    assert expected == {rule.id for rule in builtin_rules()}
    labels = small(1).labels.actors.values()
    assert any(label.malicious for label in labels)
    assert sum(not label.malicious for label in labels) > 50


def test_labels_round_trip_through_json(tmp_path: Path) -> None:
    files = write_simulation(small(1), tmp_path)
    loaded = Labels.from_json(files["labels.json"].read_text(encoding="utf-8"))
    assert loaded.to_json() == small(1).labels.to_json()
    assert loaded.start == datetime(2026, 3, 2, tzinfo=UTC)


def test_rendered_line_round_trips_through_the_parser() -> None:
    hit = WebHit(
        ts=datetime(2026, 3, 2, 10, 0, 1, tzinfo=UTC),
        ip="198.18.0.1",
        method="GET",
        target="/cgi-bin/test.cgi",
        status=404,
        size=200,
        referrer="",
        user_agent='() { :;}; /bin/bash -c "echo probe"',
    )
    event = parse_combined(render_web(hit))
    assert event.user_agent == hit.user_agent
    assert event.ts == hit.ts
    assert event.referrer == ""
    assert escape_field('a"b\\c') == "a\\x22b\\x5Cc"


def test_too_short_simulation_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least 36"):
        simulate(1, hours=12)
