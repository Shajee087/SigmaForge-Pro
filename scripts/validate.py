#!/usr/bin/env python3
"""
SigmaForge Pro - Rule Validator
Walks the /rules directory, parses every Sigma YAML file with pySigma,
and checks for required fields and valid syntax. Exits non-zero (CI gate)
if any rule fails validation.

Two passes:
  1. Per-file field + standalone syntax checks.
  2. Whole-collection parse so correlation rules can resolve their
     base-rule references (name: fields in other files).
"""
import sys
import glob
import os
import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

DETECTION_RULE_FIELDS = ["title", "id", "status", "description", "logsource", "detection", "level"]
CORRELATION_RULE_FIELDS = ["title", "id", "status", "description", "correlation", "level"]
RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "rules")


def find_rule_files():
    return sorted(glob.glob(os.path.join(RULES_DIR, "**", "*.yml"), recursive=True))


def check_required_fields(raw):
    is_correlation = "correlation" in raw
    required = CORRELATION_RULE_FIELDS if is_correlation else DETECTION_RULE_FIELDS

    missing = [f for f in required if f not in raw]
    if missing:
        return f"Missing required field(s): {', '.join(missing)}"

    if is_correlation:
        return None

    if not raw.get("tags"):
        return "Missing 'tags' — every rule must map to at least one MITRE ATT&CK technique"
    if not any(str(t).startswith("attack.t") for t in raw.get("tags", [])):
        return "No ATT&CK technique tag found (expected a tag like 'attack.t1110.001')"
    return None


def main():
    rule_files = find_rule_files()
    if not rule_files:
        print("No rule files found under /rules — nothing to validate.")
        sys.exit(1)

    print(f"Validating {len(rule_files)} Sigma rule(s)...\n")

    # Pass 1: per-file field checks + individual standalone syntax check
    # (correlation rules are allowed to fail standalone name-resolution here)
    field_failures = []
    raws = {}
    for path in rule_files:
        rel = os.path.relpath(path, RULES_DIR)
        with open(path, "r") as f:
            raw = yaml.safe_load(f)
        raws[rel] = raw

        error = check_required_fields(raw)
        if error:
            field_failures.append((rel, error))
        elif "correlation" not in raw:
            try:
                SigmaCollection.from_yaml(open(path).read())
            except SigmaError as e:
                field_failures.append((rel, f"Sigma syntax error: {e}"))
            except Exception as e:
                field_failures.append((rel, f"Unexpected parse error: {e}"))

    for rel in raws:
        status = "FAIL" if rel in dict(field_failures) else "PASS"
        print(f"  [{status}] {rel}")
        if status == "FAIL":
            print(f"         -> {dict(field_failures)[rel]}")

    # Pass 2: whole-collection parse to resolve correlation base-rule references
    print("\nResolving correlation rule references across the full rule set...")
    combined_yaml = "\n---\n".join(open(p).read() for p in rule_files)
    collection_error = None
    try:
        SigmaCollection.from_yaml(combined_yaml)
        print("  [PASS] all correlation references resolved")
    except SigmaError as e:
        collection_error = f"Sigma correlation resolution error: {e}"
        print(f"  [FAIL] {collection_error}")
    except Exception as e:
        collection_error = f"Unexpected collection parse error: {e}"
        print(f"  [FAIL] {collection_error}")

    print()
    total_failures = len(field_failures) + (1 if collection_error else 0)
    if total_failures:
        print(f"VALIDATION FAILED: {len(field_failures)} file-level issue(s)"
              f"{' + 1 collection-level issue' if collection_error else ''}.")
        sys.exit(1)

    print(f"VALIDATION PASSED: all {len(rule_files)} rule(s) are valid.")
    sys.exit(0)


if __name__ == "__main__":
    main()
