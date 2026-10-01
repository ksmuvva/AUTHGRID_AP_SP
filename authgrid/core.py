from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests

DB_PATH = os.getenv("AUTHGRID_DB_PATH", "data/authgrid.db")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_dt(value: str | None) -> datetime:
    if not value:
        return utcnow()
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def stable_id(*parts: Any) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:24]


@dataclass
class Detection:
    detection_type: str
    identity: str
    severity: str
    confidence: float
    risk_contribution: int
    reason: str
    evidence_event_ids: list[str]
    rule_version: str


def connect(path: str = DB_PATH) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript("""
    CREATE TABLE IF NOT EXISTS events (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, source TEXT NOT NULL,
      source_event_id TEXT NOT NULL, event_type TEXT NOT NULL,
      occurred_at TEXT NOT NULL, received_at TEXT NOT NULL,
      identity TEXT, ip_address TEXT, country TEXT, application TEXT,
      device TEXT, outcome TEXT, raw_payload TEXT NOT NULL,
      UNIQUE(tenant_id, source, source_event_id)
    );
    CREATE TABLE IF NOT EXISTS detections (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, detection_type TEXT NOT NULL,
      identity TEXT, severity TEXT, confidence REAL, risk_contribution INTEGER,
      reason TEXT NOT NULL, evidence_event_ids TEXT NOT NULL,
      rule_version TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS checkpoints (
      tenant_id TEXT NOT NULL, source TEXT NOT NULL, stream TEXT NOT NULL,
      cursor TEXT NOT NULL, updated_at TEXT NOT NULL,
      PRIMARY KEY(tenant_id, source, stream)
    );
    """)
    db.commit()
    return db


def normalize_event(raw: dict[str, Any], tenant_id: str, event_type: str, source: str = "microsoft_entra") -> dict[str, Any]:
    status = raw.get("status") or {}
    device = raw.get("deviceDetail") or {}
    location = raw.get("location") or {}
    country = location.get("countryOrRegion") or location.get("country")
    event_id = raw.get("id") or stable_id(json.dumps(raw, sort_keys=True))
    return {
        "id": stable_id(tenant_id, source, event_id),
        "tenant_id": tenant_id,
        "source": source,
        "source_event_id": event_id,
        "event_type": event_type,
        "occurred_at": raw.get("createdDateTime") or raw.get("activityDateTime") or utcnow().isoformat(),
        "received_at": utcnow().isoformat(),
        "identity": raw.get("userPrincipalName") or raw.get("initiatedBy", {}).get("user", {}).get("userPrincipalName") or raw.get("targetResources", [{}])[0].get("userPrincipalName"),
        "ip_address": raw.get("ipAddress"),
        "country": country,
        "application": raw.get("appDisplayName") or raw.get("resourceDisplayName"),
        "device": json.dumps({k: v for k, v in device.items() if v is not None}, sort_keys=True),
        "outcome": "success" if status.get("errorCode", 0) == 0 else "failure",
        "raw_payload": json.dumps(raw, sort_keys=True),
    }


def save_events(db: sqlite3.Connection, events: list[dict[str, Any]]) -> int:
    count = 0
    for e in events:
        cur = db.execute("""INSERT OR IGNORE INTO events
          (id, tenant_id, source, source_event_id, event_type, occurred_at, received_at,
           identity, ip_address, country, application, device, outcome, raw_payload)
          VALUES (:id, :tenant_id, :source, :source_event_id, :event_type, :occurred_at,
           :received_at, :identity, :ip_address, :country, :application, :device,
           :outcome, :raw_payload)""", e)
        count += cur.rowcount
    db.commit()
    return count


def _graph_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    response = requests.post(
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        data={"client_id": client_id, "client_secret": client_secret,
              "scope": "https://graph.microsoft.com/.default", "grant_type": "client_credentials"},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["access_token"]


def _graph_pages(url: str, headers: dict[str, str], params: dict[str, str]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    next_url: str | None = url
    first = True
    for attempt in range(4):
        while next_url:
            response = requests.get(next_url, headers=headers, params=params if first else None, timeout=30)
            first = False
            if response.status_code in (429, 500, 502, 503, 504):
                retry_after = int(response.headers.get("Retry-After", "2"))
                time.sleep(min(retry_after, 10))
                continue
            response.raise_for_status()
            body = response.json()
            items.extend(body.get("value", []))
            next_url = body.get("@odata.nextLink")
        return items
    raise RuntimeError("Microsoft Graph did not become available after retries")


def sync_entra(tenant_id: str, client_id: str, client_secret: str, since: datetime, until: datetime | None = None, db_path: str = DB_PATH) -> dict[str, int]:
    until = until or utcnow()
    token = _graph_token(tenant_id, client_id, client_secret)
    headers = {"Authorization": f"Bearer {token}"}
    start = since.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    end = until.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    filt = f"createdDateTime ge {start} and createdDateTime le {end}"
    raw_signins = _graph_pages("https://graph.microsoft.com/v1.0/auditLogs/signIns", headers, {"$filter": filt, "$top": "1000"})
    raw_audits = _graph_pages("https://graph.microsoft.com/v1.0/auditLogs/directoryAudits", headers, {"$filter": f"activityDateTime ge {start} and activityDateTime le {end}", "$top": "1000"})
    events = [normalize_event(x, tenant_id, "sign_in") for x in raw_signins]
    events += [normalize_event(x, tenant_id, "directory_audit") for x in raw_audits]
    saved = save_events(connect(db_path), events)
    return {"sign_ins": len(raw_signins), "directory_audits": len(raw_audits), "new_events": saved}


def seed_demo(db_path: str = DB_PATH, tenant_id: str = "demo-tenant") -> int:
    fixture_path = Path(__file__).resolve().parent.parent / "data" / "synthetic_events.json"
    if fixture_path.exists():
        fixture_events = json.loads(fixture_path.read_text())
        events = [normalize_event(raw, tenant_id, "sign_in", "demo") for raw in fixture_events]
        return save_events(connect(db_path), events)

    now = utcnow()
    def ev(i: str, minutes: int, identity: str, ip: str, country: str, outcome: str, app: str = "Microsoft 365", device: str = "Windows") -> dict[str, Any]:
        raw = {"id": i, "createdDateTime": (now - timedelta(minutes=minutes)).isoformat(), "userPrincipalName": identity,
               "ipAddress": ip, "appDisplayName": app, "status": {"errorCode": 0 if outcome == "success" else 50126},
               "location": {"countryOrRegion": country}, "deviceDetail": {"displayName": device, "operatingSystem": "Windows 11"}}
        return normalize_event(raw, tenant_id, "sign_in", "demo")
    events = [
        ev("demo-1", 5, "alice@contoso.test", "203.0.113.10", "GB", "success"),
        ev("demo-2", 8, "alice@contoso.test", "198.51.100.44", "SG", "success", device="Unknown"),
        ev("demo-3", 14, "bob@contoso.test", "192.0.2.50", "US", "failure"),
        ev("demo-4", 13, "bob@contoso.test", "192.0.2.50", "US", "failure"),
        ev("demo-5", 12, "bob@contoso.test", "192.0.2.50", "US", "failure"),
        ev("demo-6", 10, "bob@contoso.test", "192.0.2.50", "US", "success"),
        ev("demo-7", 6, "carol@contoso.test", "192.0.2.50", "US", "failure"),
        ev("demo-8", 5, "dave@contoso.test", "192.0.2.50", "US", "failure"),
    ]
    return save_events(connect(db_path), events)


def load_events(db: sqlite3.Connection, tenant_id: str | None = None) -> list[dict[str, Any]]:
    query = "SELECT * FROM events"
    params: tuple[Any, ...] = ()
    if tenant_id:
        query += " WHERE tenant_id = ?"
        params = (tenant_id,)
    query += " ORDER BY occurred_at DESC"
    return [dict(x) for x in db.execute(query, params).fetchall()]


def run_detections(db_path: str = DB_PATH, tenant_id: str | None = None) -> list[Detection]:
    events = load_events(connect(db_path), tenant_id)
    by_identity: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in events:
        if e["identity"]:
            by_identity[e["identity"]].append(e)
        if e["ip_address"]:
            by_ip[e["ip_address"]].append(e)
    found: list[Detection] = []
    for identity, rows in by_identity.items():
        rows.sort(key=lambda x: x["occurred_at"])
        failures = [r for r in rows if r["outcome"] == "failure"]
        successes = [r for r in rows if r["outcome"] == "success"]
        if len(failures) >= 3:
            evidence = [r["id"] for r in failures[-3:]]
            found.append(Detection("repeated_failures", identity, "medium", .92, 20, f"{len(failures)} failed sign-ins were observed for {identity}.", evidence, "repeated-failures-v1"))
        if failures and successes and any(f["occurred_at"] < successes[-1]["occurred_at"] for f in failures):
            evidence = [r["id"] for r in failures[-3:]] + [successes[-1]["id"]]
            found.append(Detection("success_after_failures", identity, "high", .95, 25, f"A successful sign-in followed repeated failures for {identity}.", evidence, "success-after-failures-v1"))
        countries = {r["country"] for r in successes if r["country"]}
        if len(countries) >= 2:
            evidence = [r["id"] for r in successes[-2:]]
            found.append(Detection("unusual_location", identity, "high", .82, 20, f"Successful sign-ins for {identity} were observed in multiple countries: {', '.join(sorted(countries))}.", evidence, "unusual-location-v1"))
    for ip, rows in by_ip.items():
        identities = {r["identity"] for r in rows if r["identity"]}
        failures = [r for r in rows if r["outcome"] == "failure"]
        if len(identities) >= 3 and len(failures) >= 3:
            evidence = [r["id"] for r in failures[:6]]
            found.append(Detection("password_spray", "multiple identities", "high", .90, 30, f"IP {ip} generated failures against {len(identities)} identities.", evidence, "password-spray-v1"))
    db = connect(db_path)
    for d in found:
        tenant = tenant_id or (events[0]["tenant_id"] if events else "demo-tenant")
        db.execute("INSERT OR REPLACE INTO detections VALUES (?,?,?,?,?,?,?,?,?,?,?)", (stable_id(tenant, d.detection_type, d.identity, *d.evidence_event_ids), tenant, d.detection_type, d.identity, d.severity, d.confidence, d.risk_contribution, d.reason, json.dumps(d.evidence_event_ids), d.rule_version, utcnow().isoformat()))
    db.commit()
    return found


def load_detections(db_path: str = DB_PATH, tenant_id: str | None = None) -> list[dict[str, Any]]:
    db = connect(db_path)
    query = "SELECT * FROM detections"
    params: tuple[Any, ...] = ()
    if tenant_id:
        query += " WHERE tenant_id = ?"
        params = (tenant_id,)
    query += " ORDER BY created_at DESC"
    return [dict(x) for x in db.execute(query, params).fetchall()]
