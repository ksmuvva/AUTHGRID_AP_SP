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

- **Deterministic rules:** the four detection types listed below.
- **ML anomaly signal:** `ml_identity_anomaly`, scored with Isolation Forest when enough events exist, with a transparent feature-based fallback for small datasets.

### Detection types currently implemented

| Detection type | Version | What it detects | Default severity | Risk contribution |
|---|---|---|---|---:|
| `repeated_failures` | `repeated-failures-v1` | Three or more failed sign-ins for one identity | Medium | 20 |
| `success_after_failures` | `success-after-failures-v1` | A successful sign-in after earlier failed sign-ins for the same identity | High | 25 |
| `unusual_location` | `unusual-location-v1` | Successful sign-ins for one identity from multiple countries | High | 20 |
| `password_spray` | `password-spray-v1` | Failed sign-ins from one IP against at least three identities | High | 30 |
| `ml_identity_anomaly` | `isolation-forest-v1` | Behavioural deviation based on identity, IP, country, device, application, time and failure-pattern features | Medium or High | Up to 25 |

### ML feature signals

The current ML detector evaluates these explainable signals:

- new country;
- new IP address;
- new device;
- new application;
- unusual sign-in time, currently before 06:00 or at/after 22:00 UTC;
- recent failure burst;
- IP shared by multiple identities;
- current event outcome is a failure.

The ML finding stores the anomaly score, model version, contributing signals and source event ID. It is an additional risk signal and does not independently trigger an account action.

An LLM investigation assistant is intentionally not connected yet; it should explain and correlate evidence after the detection layer is evaluated.

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
