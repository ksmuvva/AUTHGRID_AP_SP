# AuthGrid Functional POC — Streamlit + VS Code

This POC demonstrates the core flow:

```text
Microsoft Entra Graph API or committed synthetic fixtures
        ↓
Normalize and persist events
        ↓
Run deterministic rules and ML anomaly detection
        ↓
Explainable risk findings with evidence
        ↓
Streamlit developer/demo UI
```

## Run locally

```bash
cd /home/ubuntu/authgrid-poc
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Open the URL shown by Streamlit. The default **Demo mode** works without Microsoft credentials.

The committed test dataset is [`data/synthetic_events.json`](data/synthetic_events.json). It contains sanitized, non-production Entra-like events designed to demonstrate unusual location, repeated failures, success after failures, and password-spray findings.

## Optional Microsoft Entra mode

Create a Microsoft Graph application with application permission `AuditLog.Read.All` and admin consent, then create `.env`:

```env
ENTRA_TENANT_ID=your-tenant-id
ENTRA_CLIENT_ID=your-client-id
ENTRA_CLIENT_SECRET=your-client-secret
```

Run the app, select **Microsoft Entra / Graph** in the sidebar, choose a time window, and click **Sync Entra logs**.

The POC reads:

- `GET /v1.0/auditLogs/signIns`
- `GET /v1.0/auditLogs/directoryAudits`

The connector uses bounded time filters, pagination, retries, and local deduplication. Keep secrets in `.env`; never commit them.

## Hybrid detection model

The POC now produces two types of findings:

- **Deterministic rules:** repeated failures, password spray, success after failures, and unusual location.
- **ML anomaly signal:** point-in-time identity features scored with Isolation Forest when enough events exist, with a transparent feature-based fallback for small datasets.

ML findings are stored as `ml_identity_anomaly`, include the model version and contributing signals, and link to the source event used as evidence. They are an additional risk signal—not an autonomous account-action decision. An LLM investigation assistant is intentionally not connected yet; it should explain and correlate evidence after the detection layer is evaluated.

## Run tests

```bash
pytest -q
```

## POC limitations

- SQLite is used for local demonstration.
- This is not production-ready multi-tenant infrastructure.
- Graph polling is used instead of Event Hub streaming.
- The ML layer is a prototype anomaly signal, not a validated production model.
- A production design should add labelled evaluation, false-positive monitoring, drift monitoring, per-tenant baselines, and human review before ML affects automated actions.
- Response actions are not implemented.
