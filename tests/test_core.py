import json
from pathlib import Path

from authgrid.core import connect, normalize_event, run_detections, save_events, seed_demo


def test_normalize_event_has_source_identity():
    raw = {"id": "x1", "createdDateTime": "2026-09-30T10:00:00Z", "userPrincipalName": "a@test", "ipAddress": "1.2.3.4", "status": {"errorCode": 0}, "location": {"countryOrRegion": "GB"}}
    event = normalize_event(raw, "t1", "sign_in")
    assert event["source_event_id"] == "x1"
    assert event["outcome"] == "success"
    assert event["country"] == "GB"


def test_save_events_is_idempotent(tmp_path: Path):
    db_path = str(tmp_path / "test.db")
    db = connect(db_path)
    event = normalize_event({"id": "x1", "createdDateTime": "2026-09-30T10:00:00Z"}, "t1", "sign_in")
    assert save_events(db, [event, event]) == 1
    assert save_events(db, [event]) == 0


def test_demo_produces_evidence_backed_findings(tmp_path: Path):
    db_path = str(tmp_path / "test.db")
    seed_demo(db_path)
    findings = run_detections(db_path, "demo-tenant")
    assert findings
    assert any(x.detection_type == "password_spray" for x in findings)
    assert any(x.detection_type == "ml_identity_anomaly" for x in findings)
    assert all(x.evidence_event_ids for x in findings)
