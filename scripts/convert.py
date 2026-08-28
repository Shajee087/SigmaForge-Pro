#!/usr/bin/env python3
"""
SigmaForge Pro - Rule Converter
Converts Sigma rules under /rules into Wazuh-compatible output:
  - Standalone detection rules -> Elasticsearch/Lucene query (JSON)
  - Correlation rules -> Wazuh <frequency>/<timeout> rule XML stub,
    since Wazuh implements threshold correlation natively rather than
    via a stateless query language (pySigma's ES backend has no
    correlation support, matching real-world SIEM behavior).
"""
import os
import glob
import json
import sys
import yaml
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch import LuceneBackend

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "rules")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "converted")

# Wazuh custom rule IDs start at 100000+ by convention
WAZUH_RULE_ID_START = 100500


def find_rule_files():
    return sorted(glob.glob(os.path.join(RULES_DIR, "**", "*.yml"), recursive=True))


def is_correlation(raw):
    return "correlation" in raw


def convert_detection_rules(detection_paths, backend):
    converted = 0
    for path, raw in detection_paths:
        rel = os.path.relpath(path, RULES_DIR)
        rel_no_ext = os.path.splitext(rel)[0]
        out_path = os.path.join(OUTPUT_DIR, rel_no_ext + ".json")
        os.makedirs(os.path.dirname(out_path), exist_ok=True)

        collection = SigmaCollection.from_yaml(open(path).read())
        query = backend.convert(collection)[0]

        with open(out_path, "w") as f:
            json.dump({
                "source_rule": rel,
                "rule_id": raw.get("id"),
                "level": raw.get("level"),
                "type": "lucene_query",
                "query": query
            }, f, indent=2)

        print(f"  [OK]   {rel} -> converted/{rel_no_ext}.json  (Lucene query)")
        converted += 1
    return converted


def wazuh_level_from_sigma(level):
    mapping = {"low": 3, "medium": 7, "high": 10, "critical": 13}
    return mapping.get(level, 5)


def build_wazuh_frequency_stub(rel_no_ext, raw, rule_id_num):
    corr = raw["correlation"]
    corr_type = corr.get("type", "event_count")
    base_rules = corr.get("rules", [])
    group_by = corr.get("group-by", [])
    timespan = corr.get("timespan", "5m")
    condition = corr.get("condition", {})
    threshold = condition.get("gte", 5)

    # timespan like "5m" / "1h" -> seconds
    unit = timespan[-1]
    amount = int(timespan[:-1])
    seconds = amount * {"s": 1, "m": 60, "h": 3600}.get(unit, 60)

    same_fields = "\n        ".join(f"<same_field>{f}</same_field>" for f in group_by)

    xml = f"""<!-- Auto-generated from Sigma correlation rule: {raw.get('title')} -->
<!-- Base event rule name(s) referenced: {', '.join(base_rules)} -->
<!-- Correlation type: {corr_type} | group-by: {group_by} | threshold: >= {threshold} in {timespan} -->
<rule id="{rule_id_num}" level="{wazuh_level_from_sigma(raw.get('level'))}">
    <if_matched_sid>BASE_RULE_ID_FOR_{base_rules[0] if base_rules else 'UNKNOWN'}</if_matched_sid>
    <same_source_ip />
    {same_fields}
    <frequency>{threshold}</frequency>
    <timeframe>{seconds}</timeframe>
    <description>{raw.get('title')}</description>
    <mitre>
        {"".join(f'<id>{t.split("attack.t")[1].upper()}</id>' for t in raw.get('tags', []) if str(t).startswith('attack.t'))}
    </mitre>
</rule>
<!-- NOTE: replace BASE_RULE_ID_FOR_* with the actual Wazuh rule ID assigned
     to the base event rule once it is loaded into Wazuh's ruleset. -->
"""
    return xml


def convert_correlation_rules(correlation_paths):
    converted = 0
    rule_id_counter = WAZUH_RULE_ID_START
    for path, raw in correlation_paths:
        rel = os.path.relpath(path, RULES_DIR)
        rel_no_ext = os.path.splitext(rel)[0]
        out_path = os.path.join(OUTPUT_DIR, rel_no_ext + ".xml")
        os.makedirs(os.path.dirname(out_path), exist_ok=True)

        xml = build_wazuh_frequency_stub(rel_no_ext, raw, rule_id_counter)
        with open(out_path, "w") as f:
            f.write(xml)

        print(f"  [OK]   {rel} -> converted/{rel_no_ext}.xml  (Wazuh frequency rule)")
        converted += 1
        rule_id_counter += 1
    return converted


def main():
    rule_files = find_rule_files()
    if not rule_files:
        print("No rules found to convert.")
        sys.exit(1)

    print(f"Converting {len(rule_files)} rule(s)...\n")

    detection_paths, correlation_paths = [], []
    for path in rule_files:
        with open(path) as f:
            raw = yaml.safe_load(f)
        (correlation_paths if is_correlation(raw) else detection_paths).append((path, raw))

    backend = LuceneBackend()
    n1 = convert_detection_rules(detection_paths, backend)
    n2 = convert_correlation_rules(correlation_paths)

    print(f"\nDone. {n1} Lucene quer{'y' if n1 == 1 else 'ies'} + {n2} Wazuh frequency rule stub(s) generated.")
    sys.exit(0)


if __name__ == "__main__":
    main()
