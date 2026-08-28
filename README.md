# SigmaForge Pro
 **Live Demo:** [sigmaforge-pro.streamlit.app](https://sigmaforge-pro.streamlit.app/)

**A Detection-as-Code CI/CD pipeline for Sigma rules.**

Built as an advanced follow-up to [SigmaForge-Lite](https://github.com/Shajee087/sigmaforge-lite), this project turns Sigma
rule authoring into a proper software engineering workflow: every rule is
validated, converted, and automatically tested against sample logs before it's
allowed to merge — the same way SOC and detection engineering teams manage
production detection content.

## Why this exists

Most student detection-engineering projects stop at "I wrote a Sigma rule."
Real detection engineering teams treat rules like code: version-controlled,
peer-reviewed, unit-tested, and shipped through CI/CD with rollback and
coverage tracking. SigmaForge Pro implements that full loop end-to-end.

## Architecture

```
sigmaforge-pro/
├── rules/                      # Sigma rules, organized by MITRE ATT&CK tactic
│   ├── credential_access/
│   ├── persistence/
│   ├── defense_evasion/
│   ├── lateral_movement/
│   ├── execution/
│   ├── command_and_control/
│   └── exfiltration/
├── tests/
│   └── fixtures.json           # True-positive / false-positive sample logs
├── converted/                  # Generated: Lucene queries + Wazuh rule stubs
├── scripts/
│   ├── validate.py             # Syntax + required-field validation
│   ├── convert.py              # Sigma -> Elasticsearch/Lucene + Wazuh frequency rules
│   ├── test_detections.py      # Runs rule logic against sample logs
│   └── generate_attack_layer.py# Builds ATT&CK Navigator coverage heatmap
├── dashboard/
│   └── app.py                  # Streamlit dashboard: catalog + coverage view
└── .github/workflows/ci.yml    # CI/CD pipeline runs on every push to /rules
```

## Pipeline stages

1. **Author**  Write a Sigma rule under `/rules/<tactic>/`, tagged with a
   MITRE ATT&CK technique ID.
2. **Validate**  `validate.py` checks required fields and Sigma syntax. For
   correlation rules (e.g. "5 failed SSH logins in 5 minutes"), it resolves
   base-event references across the whole rule collection.
3. **Convert**  `convert.py` compiles standalone rules to
   Elasticsearch/Lucene queries and correlation rules to Wazuh
   `<frequency>/<timeout>` rule stubs — because Wazuh implements threshold
   correlation natively rather than through a stateless query, which is a
   real constraint detection engineers work around.
4. **Test**  `test_detections.py` evaluates each rule's selection logic
   against paired true-positive/false-positive log fixtures, catching logic
   regressions before they reach production.
5. **Map coverage**  `generate_attack_layer.py` builds a MITRE ATT&CK
   Navigator layer showing exactly which techniques the rule set detects.
6. **Ship**  GitHub Actions runs all of the above on every push/PR touching
   `/rules`. A failing rule blocks the merge.

## Rule set

17 rules across 7 tactics (13 standalone detections + 4 threshold
correlations), covering 14 distinct MITRE ATT&CK techniques — including
credential dumping (LSASS access), SSH brute force, encoded PowerShell,
web shell spawning, DNS tunneling, C2 beaconing, and data exfiltration.

## Running it locally

```bash
pip install -r requirements.txt
python scripts/validate.py
python scripts/convert.py
python scripts/test_detections.py
python scripts/generate_attack_layer.py
streamlit run dashboard/app.py
```

## Tech stack

Python, pySigma, pysigma-backend-elasticsearch, PyYAML, GitHub Actions,
Streamlit, MITRE ATT&CK Navigator layer format.

## Author

Shajee Mushtaque BS Cybersecurity, Mehran University of Engineering and
Technology (MUET). GitHub: [Shajee087](https://github.com/Shajee087)
