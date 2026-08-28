#!/usr/bin/env python3
"""
SigmaForge Pro - ATT&CK Coverage Heatmap Generator
Scans all rules under /rules, extracts attack.t#### tags, and builds a
MITRE ATT&CK Navigator layer JSON showing which techniques the rule set
covers. Upload the output file at https://mitre-attack.github.io/attack-navigator/
to visualize coverage.
"""
import os
import glob
import json
import yaml
from collections import defaultdict

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "rules")
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "converted", "attack_navigator_layer.json")


def find_rule_files():
    return sorted(glob.glob(os.path.join(RULES_DIR, "**", "*.yml"), recursive=True))


def extract_technique_ids(tags):
    ids = []
    for tag in tags or []:
        tag = str(tag)
        if tag.startswith("attack.t"):
            technique = tag.replace("attack.t", "T").upper()
            ids.append(technique)
    return ids


def main():
    technique_rules = defaultdict(list)

    for path in find_rule_files():
        with open(path) as f:
            raw = yaml.safe_load(f)
        rel = os.path.relpath(path, RULES_DIR)
        for tid in extract_technique_ids(raw.get("tags")):
            technique_rules[tid].append(raw.get("title", rel))

    techniques = []
    for tid, rule_titles in sorted(technique_rules.items()):
        techniques.append({
            "techniqueID": tid,
            "score": len(rule_titles),
            "color": "",
            "comment": "Detected by: " + "; ".join(rule_titles),
            "enabled": True,
            "metadata": [],
            "showSubtechniques": False
        })

    layer = {
        "name": "SigmaForge Pro - Detection Coverage",
        "versions": {"attack": "15", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Auto-generated coverage layer from SigmaForge Pro Sigma rule set.",
        "sorting": 3,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "gradient": {
            "colors": ["#8ec843", "#ffe766", "#ff6666"],
            "minValue": 0,
            "maxValue": 3
        },
        "legendItems": [],
        "techniques": techniques,
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True
    }

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(layer, f, indent=2)

    print(f"Coverage layer generated: {len(techniques)} unique technique(s) covered "
          f"across {sum(len(v) for v in technique_rules.values())} rule mapping(s).")
    print(f"Written to converted/attack_navigator_layer.json")
    print("Upload it at https://mitre-attack.github.io/attack-navigator/ to visualize.")


if __name__ == "__main__":
    main()
