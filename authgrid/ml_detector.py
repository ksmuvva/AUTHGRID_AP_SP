from __future__ import annotations

from typing import Any

from .core import Detection
from .features import build_features

MODEL_VERSION = "isolation-forest-v1"


def detect_anomalies(events: list[dict[str, Any]]) -> list[Detection]:
    """Return ML anomaly signals; deterministic rules remain authoritative.

    IsolationForest is used when enough events exist. A transparent feature score is
    retained as a fallback and explanation so the POC remains runnable on small data.
    """
    rows = build_features(events)
    if not rows:
        return []
    model_scores = [0.0] * len(rows)
    if len(rows) >= 5:
        try:
            from sklearn.ensemble import IsolationForest
            model = IsolationForest(n_estimators=100, contamination=min(0.25, max(1 / len(rows), 0.05)), random_state=42)
            model.fit([row["vector"] for row in rows])
            raw = [-float(x) for x in model.decision_function([row["vector"] for row in rows])]
            low, high = min(raw), max(raw)
            span = high - low or 1.0
            model_scores = [(x - low) / span for x in raw]
        except ImportError:
            model_scores = [0.0] * len(rows)
    findings: list[Detection] = []
    for index, row in enumerate(rows):
        heuristic = min(1.0, sum(row["vector"][:5]) * 0.22 + row["vector"][5] * 0.25 + row["vector"][6] * 0.25 + row["vector"][7] * 0.08)
        score = max(model_scores[index] * 0.65 + heuristic * 0.35, heuristic)
        if score < 0.45:
            continue
        event = row["event"]
        severity = "high" if score >= 0.75 else "medium"
        signals = ", ".join(row["signals"]) or "combined behavioural deviation"
        findings.append(Detection(
            "ml_identity_anomaly", row["identity"], severity, round(min(score, 0.99), 2),
            max(1, round(score * 25)),
            f"ML anomaly score {score:.2f}; contributing signals: {signals}.",
            [event["id"]], MODEL_VERSION,
        ))
    return findings
