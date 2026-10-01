from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _device_name(event: dict[str, Any]) -> str:
    try:
        return json.loads(event.get("device") or "{}").get("displayName") or ""
    except json.JSONDecodeError:
        return ""


def build_features(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build explainable, point-in-time features; no future events leak into a row."""
    ordered = sorted(events, key=lambda e: e["occurred_at"])
    history: dict[str, list[dict[str, Any]]] = defaultdict(list)
    rows: list[dict[str, Any]] = []
    for event in ordered:
        identity = event.get("identity") or "unknown"
        prior = history[identity]
        current_time = _dt(event["occurred_at"])
        recent = [x for x in prior if (current_time - _dt(x["occurred_at"])).total_seconds() <= 86400]
        prior_countries = {x.get("country") for x in recent if x.get("country")}
        prior_ips = {x.get("ip_address") for x in recent if x.get("ip_address")}
        prior_apps = {x.get("application") for x in recent if x.get("application")}
        prior_devices = {_device_name(x) for x in recent if _device_name(x)}
        same_ip_identities = {x.get("identity") for x in ordered if x.get("ip_address") == event.get("ip_address") and x.get("identity")}
        failure_count = sum(1 for x in recent if x.get("outcome") == "failure")
        hour = current_time.hour + current_time.minute / 60
        signals: list[str] = []
        new_country = int(bool(event.get("country") and event.get("country") not in prior_countries))
        new_ip = int(bool(event.get("ip_address") and event.get("ip_address") not in prior_ips))
        new_app = int(bool(event.get("application") and event.get("application") not in prior_apps))
        device = _device_name(event)
        new_device = int(bool(device and device not in prior_devices))
        off_hours = int(hour < 6 or hour >= 22)
        if new_country: signals.append("new country")
        if new_ip: signals.append("new IP")
        if new_device: signals.append("new device")
        if new_app: signals.append("new application")
        if off_hours: signals.append("unusual sign-in time")
        if failure_count >= 3: signals.append("recent failure burst")
        if len(same_ip_identities) >= 3: signals.append("IP shared by multiple identities")
        vector = [new_country, new_ip, new_device, new_app, off_hours, min(failure_count, 10) / 10, min(len(same_ip_identities), 10) / 10, 1 if event.get("outcome") == "failure" else 0]
        rows.append({"event": event, "vector": vector, "signals": signals, "identity": identity})
        history[identity].append(event)
    return rows
