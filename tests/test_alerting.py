#!/usr/bin/env python3
"""Tests for cyber_estate's alert debounce, hold and rate limit (alerting.py).

FOUR SILENT FAILURE MODES ARE COVERED HERE.

The first is a debounce that is not consecutive. A running total would confirm
a host that answered two sweeps a week apart -- exactly the passing phone the
debounce exists to ignore. So a single miss must reset the rise, and a single
sighting must reset the fall.

The second is a hold that loses the change it deferred. A flag that refuses a
flip inside its hold and then forgets it was asked would sit `off` over a
confirmed intruder until the NEXT sweep happened to re-propose. The deferred
proposal must be applied at the first proposal after expiry, and counted.

The third is a rate limiter with one shared budget, where a chatty `cleared`
stream spends the budget a `vulnerability_actionable` needed. Per type, and
every drop counted per type.

The fourth is a form that shows one number while the monitor runs on another.
`resolve_policy` is the single accessor for both, so it is checked for the
clamps and the defaults directly, and the options step is JOINED against
strings.json rather than eyeballed.

THE SELF-TEST AT THE END PROVES THESE CHECKS CAN FAIL.

Run: python3 tests/test_alerting.py
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
COMPONENT = os.path.join(HERE, "..")


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(COMPONENT, filename))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


alerting = load("ce_alerting", "alerting.py")

AlertPolicy = alerting.AlertPolicy
Debouncer = alerting.Debouncer
HeldFlag = alerting.HeldFlag
EventRateLimiter = alerting.EventRateLimiter
resolve_policy = alerting.resolve_policy

FAILURES: list[str] = []


def check(cond, msg):
    if not cond:
        FAILURES.append(msg)


# ---------------------------------------------------------------- debouncer


def test_debounce_rise_is_consecutive():
    d = Debouncer()
    p = AlertPolicy(confirm_observations=3, clear_observations=2)
    check(not d.observe({"a"}, p), "1st sighting must not confirm at confirm=3")
    check(not d.observe({"a"}, p), "2nd sighting must not confirm at confirm=3")
    t = d.observe({"a"}, p)
    check(t.asserted == ["a"], f"3rd consecutive sighting confirms: {t}")
    check(d.confirmed == frozenset({"a"}), "confirmed set holds the key")
    check(not d.observe({"a"}, p), "a confirmed key does not re-assert")


def test_debounce_miss_resets_rise():
    d = Debouncer()
    p = AlertPolicy(confirm_observations=2, clear_observations=1)
    d.observe({"a"}, p)
    check(d.pending == {"a": 1}, "pending after one sighting")
    d.observe(set(), p)
    check(d.pending == {}, "a miss forgets the pending count")
    t = d.observe({"a"}, p)
    check(not t.asserted, "a sighting after a miss starts again from one")
    t = d.observe({"a"}, p)
    check(t.asserted == ["a"], "two consecutive sightings after the reset confirm")


def test_debounce_fall_is_consecutive_and_resettable():
    d = Debouncer()
    p = AlertPolicy(confirm_observations=1, clear_observations=3)
    check(d.observe({"a"}, p).asserted == ["a"], "confirm=1 asserts on first sight")
    check(not d.observe(set(), p), "1st miss must not clear at clear=3")
    check(d.clearing == {"a": 1}, "clearing count visible")
    check(not d.observe(set(), p), "2nd miss must not clear")
    check(not d.observe({"a"}, p), "a sighting resets the fall")
    check(d.clearing == {}, "clearing count reset on sighting")
    d.observe(set(), p)
    d.observe(set(), p)
    t = d.observe(set(), p)
    check(t.cleared == ["a"], f"3rd consecutive miss clears: {t}")
    check(d.confirmed == frozenset(), "cleared key leaves the confirmed set")


def test_debounce_edges_at_one():
    """confirm=1 / clear=1 never counted a pending or falling key -- the
    threshold path must not assume one was inserted (found live: KeyError)."""
    d = Debouncer()
    p = AlertPolicy(confirm_observations=1, clear_observations=1)
    check(d.observe({"a"}, p).asserted == ["a"], "asserts on first sight")
    check(d.pending == {}, "nothing pending at confirm=1")
    check(d.observe(set(), p).cleared == ["a"], "clears on first miss")
    check(d.clearing == {}, "nothing clearing at clear=1")


def test_debounce_keys_are_independent():
    d = Debouncer()
    p = AlertPolicy(confirm_observations=2, clear_observations=2)
    d.observe({"a"}, p)
    t = d.observe({"a", "b"}, p)
    check(t.asserted == ["a"], "a confirms on its 2nd; b has only one")
    t = d.observe({"b"}, p)
    check(t.asserted == ["b"] and not t.cleared, "b confirms; a starts falling")
    t = d.observe({"b"}, p)
    check(t.cleared == ["a"], "a clears on its 2nd miss while b holds")


def test_debounce_policy_read_each_observation():
    d = Debouncer()
    d.observe({"a"}, AlertPolicy(confirm_observations=5))
    t = d.observe({"a"}, AlertPolicy(confirm_observations=2))
    check(t.asserted == ["a"], "lowering the threshold confirms on the next sweep")


def test_debounce_seed_is_silent_and_clears_normally():
    d = Debouncer()
    p = AlertPolicy(confirm_observations=2, clear_observations=1)
    d.seed({"a"})
    check(d.confirmed == frozenset({"a"}), "seeded key is confirmed")
    t = d.observe({"a"}, p)
    check(not t.asserted, "a seeded key is never announced as new")
    t = d.observe(set(), p)
    check(t.cleared == ["a"], "a seeded key clears through the ordinary fall")


def test_debounce_forget_reports_nothing():
    d = Debouncer()
    p = AlertPolicy(confirm_observations=1, clear_observations=1)
    d.observe({"a", "b"}, p)
    d.forget({"a"})
    check(d.confirmed == frozenset({"b"}), "forget drops the key")
    t = d.observe({"b"}, p)
    check(not t.cleared, "a forgotten key never reports a clear")


# --------------------------------------------------------------- held flag


def test_hold_defers_and_applies_after_expiry():
    f = HeldFlag()
    p = AlertPolicy(min_hold_seconds=300)
    check(f.propose(True, 1000.0, p) is True, "first proposal is never held")
    check(f.held_until == 1300.0, "hold runs from the change")
    check(f.propose(False, 1100.0, p) is True, "a flip inside the hold is refused")
    check(f.deferred == 1, "the refusal is counted")
    check(f.propose(False, 1299.9, p) is True, "still held one tick before expiry")
    check(f.deferred == 2, "counted again")
    check(f.propose(False, 1300.0, p) is False, "applied at expiry")
    check(f.held_until == 1600.0, "a new hold starts from the second change")


def test_hold_zero_is_no_hold():
    f = HeldFlag()
    p = AlertPolicy(min_hold_seconds=0)
    f.propose(True, 1.0, p)
    check(f.held_until is None, "no hold means no deadline")
    check(f.propose(False, 1.0, p) is False, "flips freely at hold 0")
    check(f.deferred == 0, "nothing deferred")


def test_hold_same_value_is_not_a_change():
    f = HeldFlag()
    p = AlertPolicy(min_hold_seconds=60)
    f.propose(True, 0.0, p)
    f.propose(True, 10.0, p)
    check(f.deferred == 0, "proposing the current value is not a deferred change")
    check(f.held_until == 60.0, "and does not extend the hold")


# ------------------------------------------------------------ rate limiter


def test_rate_limit_is_per_type_and_counts_drops():
    r = EventRateLimiter(window_seconds=3600)
    p = AlertPolicy(max_events_per_hour=2)
    check(r.allow("x", 0.0, p), "1st x")
    check(r.allow("x", 1.0, p), "2nd x")
    check(not r.allow("x", 2.0, p), "3rd x within the hour is dropped")
    check(r.allow("y", 2.0, p), "y has its own budget")
    check(r.suppressed == {"x": 1}, f"drops counted per type: {r.suppressed}")
    check(r.sent_in_window("x", 2.0) == 2, "sent count in window")


def test_rate_limit_window_slides():
    r = EventRateLimiter(window_seconds=100)
    p = AlertPolicy(max_events_per_hour=1)
    check(r.allow("x", 0.0, p), "first")
    check(not r.allow("x", 99.0, p), "inside the window")
    check(r.allow("x", 100.0, p), "the oldest send has aged out at the boundary")
    check(r.sent_in_window("x", 100.0) == 1, "only the new send is in the window")


# ------------------------------------------------------------------ policy


def test_policy_defaults_and_clamps():
    d = resolve_policy(None)
    check(d.confirm_observations == alerting.DEFAULT_CONFIRM_OBSERVATIONS, "default confirm")
    check(d.min_hold_seconds == alerting.DEFAULT_MIN_HOLD_MINUTES * 60, "hold in seconds")
    c = resolve_policy(
        {
            alerting.CONF_CONFIRM_OBSERVATIONS: 0,
            alerting.CONF_CLEAR_OBSERVATIONS: 999,
            alerting.CONF_MIN_HOLD_MINUTES: -5,
            alerting.CONF_MAX_EVENTS_PER_HOUR: "three",
        }
    )
    check(c.confirm_observations == alerting.MIN_OBSERVATIONS, "0 clamps up: never assert the unobserved")
    check(c.clear_observations == alerting.MAX_OBSERVATIONS, "999 clamps down")
    check(c.min_hold_seconds == 0, "negative hold clamps to 0")
    check(c.max_events_per_hour == alerting.DEFAULT_MAX_EVENTS_PER_HOUR, "unparseable falls to default")
    s = resolve_policy({alerting.CONF_MIN_HOLD_MINUTES: "3"})
    check(s.min_hold_seconds == 180, "a numeric string from a hand-edited store counts")
    check(set(d.as_attributes()) == {
        "confirm_observations", "clear_observations", "min_hold_seconds", "max_events_per_hour"
    }, "published policy names all four numbers")


def test_alerting_step_is_translated():
    """The options step, its menu entry, its four fields and the two entity
    names all resolve in strings.json AND translations/en.json."""
    flow = open(os.path.join(COMPONENT, "config_flow.py")).read()
    check('step_id="alerting"' in flow, "config_flow has the alerting step")
    check(flow.count('"alerting"') >= 3, "alerting is on both menus and the form")
    fields = {
        alerting.CONF_CONFIRM_OBSERVATIONS,
        alerting.CONF_CLEAR_OBSERVATIONS,
        alerting.CONF_MIN_HOLD_MINUTES,
        alerting.CONF_MAX_EVENTS_PER_HOUR,
    }
    for path in ("strings.json", "translations/en.json"):
        d = json.load(open(os.path.join(COMPONENT, path)))
        steps = d["options"]["step"]
        check("alerting" in steps["init"]["menu_options"], f"{path}: menu entry")
        step = steps.get("alerting", {})
        check(set(step.get("data", {})) == fields, f"{path}: step fields {set(step.get('data', {}))}")
        check(set(step.get("data_description", {})) == fields, f"{path}: field descriptions")
        bs = d.get("entity", {}).get("binary_sensor", {})
        check({"unknown_host_present", "actionable_vulnerability"} <= set(bs), f"{path}: flag names")
    platform = open(os.path.join(COMPONENT, "binary_sensor.py")).read()
    for key in re.findall(r'_attr_translation_key = "([a-z_]+)"', platform):
        check(key in bs, f"binary_sensor translation_key {key} has a string")


# --------------------------------------------------------------- self-test


def self_test():
    """Prove the checks can fail: feed each mechanism a wrong expectation."""
    before = len(FAILURES)
    d = Debouncer()
    check(d.observe({"a"}, AlertPolicy(confirm_observations=2)).asserted == ["a"], "SELFTEST rise")
    f = HeldFlag()
    f.propose(True, 0.0, AlertPolicy(min_hold_seconds=10))
    check(f.propose(False, 1.0, AlertPolicy(min_hold_seconds=10)) is False, "SELFTEST hold")
    r = EventRateLimiter()
    r.allow("x", 0.0, AlertPolicy(max_events_per_hour=1))
    check(r.allow("x", 0.0, AlertPolicy(max_events_per_hour=1)), "SELFTEST rate")
    check(resolve_policy({alerting.CONF_CONFIRM_OBSERVATIONS: 0}).confirm_observations == 0, "SELFTEST clamp")
    produced = len(FAILURES) - before
    del FAILURES[before:]
    if produced != 4:
        FAILURES.append(f"SELF-TEST: expected 4 induced failures, got {produced}")


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    self_test()
    if FAILURES:
        for f in FAILURES:
            print("FAIL:", f)
        print(f"{len(FAILURES)} failure(s) over {len(tests)} tests")
        return 1
    print(f"ok: {len(tests)} tests, self-test proved the checks can fail")
    return 0


if __name__ == "__main__":
    sys.exit(main())
