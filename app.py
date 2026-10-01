from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from authgrid.core import connect, load_detections, load_events, run_detections, seed_demo, sync_entra

load_dotenv()
DB_PATH = os.getenv("AUTHGRID_DB_PATH", "data/authgrid.db")
st.set_page_config(page_title="AuthGrid Functional POC", page_icon="", layout="wide")

st.title("AuthGrid — Functional POC")
st.caption("VS Code–first implementation · Streamlit demonstration layer · deterministic rules + ML anomaly signals")

with st.sidebar:
    st.header("POC controls")
    mode = st.radio("Data source", ["Demo fixtures", "Microsoft Entra / Graph"])
    tenant_id = st.text_input("Tenant ID", value="demo-tenant" if mode == "Demo fixtures" else os.getenv("ENTRA_TENANT_ID", ""))
    since = st.datetime_input("Sync from", value=datetime.now() - timedelta(hours=24))
    until = st.datetime_input("Sync until", value=datetime.now())
    st.divider()
    if st.button("Initialize demo data", use_container_width=True):
        inserted = seed_demo(DB_PATH, tenant_id or "demo-tenant")
        st.success(f"Inserted {inserted} demo events")
    if mode == "Microsoft Entra / Graph":
        st.info("Requires ENTRA_TENANT_ID, ENTRA_CLIENT_ID and ENTRA_CLIENT_SECRET in .env")
        if st.button("Sync Entra logs", type="primary", use_container_width=True):
            try:
                result = sync_entra(tenant_id, os.getenv("ENTRA_CLIENT_ID", ""), os.getenv("ENTRA_CLIENT_SECRET", ""), since.replace(tzinfo=timezone.utc), until.replace(tzinfo=timezone.utc), DB_PATH)
                st.success(result)
            except Exception as exc:
                st.error(f"Entra sync failed: {exc}")
    if st.button("Run detections", use_container_width=True):
        findings = run_detections(DB_PATH, tenant_id or None)
        st.success(f"Generated {len(findings)} findings")
    st.caption("This is a local POC. Do not use production secrets or customer data here.")

# Ensure a first-run demo is immediately usable.
if not Path(DB_PATH).exists():
    seed_demo(DB_PATH, tenant_id or "demo-tenant")

conn = connect(DB_PATH)
events = load_events(conn, tenant_id or None)
detections = load_detections(DB_PATH, tenant_id or None)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Events", len(events))
c2.metric("Findings", len(detections))
c3.metric("High severity", sum(1 for d in detections if d["severity"] == "high"))
c4.metric("Data source", "Demo" if mode == "Demo fixtures" else "Graph")

if not events:
    st.warning("No events found. Initialize demo data or sync Microsoft Entra logs.")
    st.stop()

tab1, tab2, tab3, tab4 = st.tabs(["Overview", "Events", "Findings", "About the POC"])

with tab1:
    st.subheader("Detection overview")
    if detections:
        summary = pd.DataFrame(detections)
        by_type = summary.groupby("detection_type").size().reset_index(name="count")
        st.bar_chart(by_type.set_index("detection_type"))
        st.dataframe(summary[["detection_type", "identity", "severity", "confidence", "risk_contribution", "reason"]], use_container_width=True, hide_index=True)
    else:
        st.info("Run detections to produce evidence-backed findings.")

with tab2:
    st.subheader("Normalized Entra events")
    event_df = pd.DataFrame(events)
    filters = st.multiselect("Outcome", sorted(event_df["outcome"].dropna().unique()), default=sorted(event_df["outcome"].dropna().unique()))
    if filters:
        event_df = event_df[event_df["outcome"].isin(filters)]
    st.dataframe(event_df[["occurred_at", "event_type", "identity", "ip_address", "country", "application", "outcome", "source_event_id"]], use_container_width=True, hide_index=True)

with tab3:
    st.subheader("Explainable findings")
    if not detections:
        st.info("No findings yet. Use Run detections in the sidebar.")
    else:
        choices = [f"{d['severity'].upper()} · {d['detection_type']} · {d['identity']}" for d in detections]
        selected = st.selectbox("Select a finding", range(len(detections)), format_func=lambda i: choices[i])
        finding = detections[selected]
        left, right = st.columns([2, 1])
        with left:
            st.markdown(f"### {finding['detection_type'].replace('_', ' ').title()}")
            st.write(finding["reason"])
            st.write(f"**Identity:** {finding['identity']}")
            st.write(f"**Rule version:** `{finding['rule_version']}`")
            st.write(f"**Evidence event IDs:** {', '.join(json.loads(finding['evidence_event_ids']))}")
        with right:
            st.metric("Severity", finding["severity"].upper())
            st.metric("Risk contribution", finding["risk_contribution"])
            st.metric("Confidence", f"{finding['confidence']:.0%}")
        evidence_ids = set(json.loads(finding["evidence_event_ids"]))
        evidence = [e for e in events if e["id"] in evidence_ids]
        st.markdown("#### Supporting evidence")
        st.dataframe(pd.DataFrame(evidence)[["occurred_at", "identity", "ip_address", "country", "application", "outcome", "source_event_id", "raw_payload"]], use_container_width=True, hide_index=True)

with tab4:
    st.subheader("What this POC proves")
    st.markdown("""
- Microsoft Entra sign-in and directory-audit events can be collected through Microsoft Graph.
- Raw source events are normalized into a canonical AuthGrid event shape.
- Duplicate source events are ignored using tenant/source/event identity.
- Deterministic detection rules and ML anomaly signals create explainable findings.
- `ml_identity_anomaly` uses point-in-time behavioural features and an Isolation Forest model when enough events exist.
- Every finding links back to source-event evidence.
- Streamlit is only a thin UI; the core logic lives in `authgrid/core.py` and can later serve React.
**Not production-ready:** this POC does not implement full tenant isolation, Event Hub streaming, enterprise RBAC, autonomous response, production model evaluation, or production secret management. An LLM investigation assistant is not yet connected; ML findings remain evidence-linked and human-reviewable.
""")
