import os
import glob
import json
import yaml
import streamlit as st
import pandas as pd

st.set_page_config(page_title="SigmaForge Pro", page_icon="🛡️", layout="wide")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(BASE_DIR, "rules")
CONVERTED_DIR = os.path.join(BASE_DIR, "converted")
LAYER_PATH = os.path.join(CONVERTED_DIR, "attack_navigator_layer.json")


@st.cache_data
def load_rules():
    rows = []
    for path in sorted(glob.glob(os.path.join(RULES_DIR, "**", "*.yml"), recursive=True)):
        with open(path) as f:
            raw = yaml.safe_load(f)
        rel = os.path.relpath(path, RULES_DIR)
        tactic_folder = rel.split(os.sep)[0]
        techniques = [t.replace("attack.t", "T").upper() for t in raw.get("tags", []) if str(t).startswith("attack.t")]
        rows.append({
            "Title": raw.get("title"),
            "Type": "Correlation" if "correlation" in raw else "Detection",
            "Tactic": tactic_folder.replace("_", " ").title(),
            "Level": raw.get("level"),
            "Status": raw.get("status"),
            "ATT&CK Techniques": ", ".join(techniques),
            "File": rel,
        })
    return pd.DataFrame(rows)


@st.cache_data
def load_coverage_layer():
    if not os.path.exists(LAYER_PATH):
        return None
    with open(LAYER_PATH) as f:
        return json.load(f)


st.title("🛡️ SigmaForge Pro")
st.caption("Detection-as-Code pipeline for Sigma rules validate, convert, test, and track ATT&CK coverage on every push.")

df = load_rules()

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Rules", len(df))
col2.metric("Detection Rules", len(df[df["Type"] == "Detection"]))
col3.metric("Correlation Rules", len(df[df["Type"] == "Correlation"]))

layer = load_coverage_layer()
technique_count = len(layer["techniques"]) if layer else 0
col4.metric("ATT&CK Techniques Covered", technique_count)

st.divider()

tab1, tab2, tab3 = st.tabs(["📋 Rule Catalog", "🎯 ATT&CK Coverage", "⚙️ Pipeline Info"])

with tab1:
    st.subheader("Rule Catalog")
    tactic_filter = st.multiselect("Filter by tactic", sorted(df["Tactic"].unique()))
    level_filter = st.multiselect("Filter by level", sorted(df["Level"].dropna().unique()))

    filtered = df.copy()
    if tactic_filter:
        filtered = filtered[filtered["Tactic"].isin(tactic_filter)]
    if level_filter:
        filtered = filtered[filtered["Level"].isin(level_filter)]

    st.dataframe(filtered, use_container_width=True, hide_index=True)

with tab2:
    st.subheader("MITRE ATT&CK Coverage")
    if layer:
        cov_df = pd.DataFrame(layer["techniques"])
        cov_df = cov_df[["techniqueID", "score", "comment"]].rename(
            columns={"techniqueID": "Technique", "score": "Rules Mapped", "comment": "Covered By"}
        )
        st.dataframe(cov_df, use_container_width=True, hide_index=True)
        st.download_button(
            "Download ATT&CK Navigator layer JSON",
            data=json.dumps(layer, indent=2),
            file_name="sigmaforge_pro_layer.json",
            mime="application/json"
        )
        st.info("Upload this file at the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to visualize the heatmap.")
    else:
        st.warning("Coverage layer not found. Run `python scripts/generate_attack_layer.py` first.")

with tab3:
    st.subheader("How this pipeline works")
    st.markdown("""
    1. **Author**  Sigma rules are written under `/rules`, tactic-organized, each tagged with a MITRE ATT&CK technique.
    2. **Validate**  `scripts/validate.py` checks required fields and Sigma syntax, resolving correlation rule references.
    3. **Convert**  `scripts/convert.py` turns standalone rules into Elasticsearch/Lucene queries (Wazuh-compatible) and correlation rules into Wazuh `<frequency>` rule stubs.
    4. **Test**  `scripts/test_detections.py` runs each rule's logic against true/false-positive sample logs.
    5. **Map**  `scripts/generate_attack_layer.py` builds an ATT&CK Navigator coverage heatmap.
    6. **CI/CD**  every push to `/rules` triggers all of the above via GitHub Actions; a failing rule blocks the merge.
    """)
    st.caption("Built by Shajee Mushtaque BS Cybersecurity, Mehran University of Engineering and Technology")
