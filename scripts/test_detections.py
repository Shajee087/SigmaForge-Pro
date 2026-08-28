#!/usr/bin/env python3
"""
SigmaForge Pro - Detection Test Harness
Evaluates each standalone detection rule's Sigma selection/condition logic
against the true_positive and false_positive log fixtures in
tests/fixtures.json, without needing a live SIEM. Correlation rules are
covered indirectly through their base-event rule's fixture.

This is a lightweight field-matching evaluator (supports |contains,
|endswith, |gte and implicit equality/OR-of-list), not a full Sigma
interpreter — good enough to catch logic regressions in CI.
"""
import os
import sys
import json
import yaml

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "rules")
FIXTURES_PATH = os.path.join(os.path.dirname(__file__), "..", "tests", "fixtures.json")


def match_single(value, expected, modifier):
    value_str = str(value)
    expected_str = str(expected)
    if modifier == "contains":
        return expected_str in value_str
    if modifier == "endswith":
        return value_str.endswith(expected_str)
    if modifier == "startswith":
        return value_str.startswith(expected_str)
    if modifier == "gte":
        return value >= expected
    if modifier == "lte":
        return value <= expected
    return value_str == expected_str


def match_value(value, expected, modifier):
    if isinstance(expected, list):
        return any(match_single(value, e, modifier) for e in expected)
    return match_single(value, expected, modifier)


def evaluate_block(block, log):
    for field_key, expected in block.items():
        field, _, modifier = field_key.partition("|")
        if field not in log:
            return False
        if not match_value(log[field], expected, modifier):
            return False
    return True


def evaluate_detection(detection, log):
    condition = detection.get("condition", "")
    namespace = {}
    for name, block in detection.items():
        if name == "condition":
            continue
        namespace[name] = evaluate_block(block, log)
    try:
        return bool(eval(condition, {"__builtins__": {}}, namespace))
    except Exception as e:
        raise RuntimeError(f"Could not evaluate condition '{condition}': {e}")


def main():
    with open(FIXTURES_PATH) as f:
        fixtures = json.load(f)

    total, passed = 0, 0
    print(f"Running detection tests for {len(fixtures)} rule(s)...\n")

    for rel_path, cases in fixtures.items():
        full_path = os.path.join(RULES_DIR, rel_path)
        if not os.path.exists(full_path):
            print(f"  [SKIP] {rel_path} — rule file not found")
            continue

        with open(full_path) as f:
            raw = yaml.safe_load(f)

        if "correlation" in raw:
            print(f"  [SKIP] {rel_path} — correlation rule, covered via base event")
            continue

        detection = raw.get("detection", {})

        for case_name, log in cases.items():
            expected_match = (case_name == "true_positive")
            total += 1
            try:
                actual_match = evaluate_detection(detection, log)
            except RuntimeError as e:
                print(f"  [ERROR] {rel_path} :: {case_name} -> {e}")
                continue

            ok = actual_match == expected_match
            status = "PASS" if ok else "FAIL"
            print(f"  [{status}] {rel_path} :: {case_name} "
                  f"(expected_match={expected_match}, got={actual_match})")
            if ok:
                passed += 1

    print(f"\n{passed}/{total} detection test case(s) passed.")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
