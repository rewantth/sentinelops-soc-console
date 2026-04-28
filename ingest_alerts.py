import json
from pathlib import Path

from app import app, alert_from_payload
from database import db
from models import Alert, TimelineEvent, now_string


def ingest_alerts():
    """Read JSON alerts and insert only new alert IDs into SQLite."""
    path = Path("data/alerts.json")
    if not path.exists():
        raise FileNotFoundError("data/alerts.json not found. Run python generate_alerts.py first.")

    alerts = json.loads(path.read_text(encoding="utf-8"))
    inserted = 0
    skipped = 0
    with app.app_context():
        for payload in alerts:
            if Alert.query.filter_by(alert_id=payload["alert_id"]).first():
                skipped += 1
                continue
            alert = alert_from_payload(payload)
            db.session.add(alert)
            db.session.flush()
            db.session.add(
                TimelineEvent(
                    alert_id=alert.alert_id,
                    event_name="alert received",
                    event_description="Alert ingested from data/alerts.json into SentinelOps.",
                    timestamp=alert.timestamp or now_string(),
                )
            )
            inserted += 1
        db.session.commit()
    return inserted, skipped


def main():
    """Run alert ingestion and print insertion results."""
    inserted, skipped = ingest_alerts()
    print(f"Inserted alerts: {inserted}")
    print(f"Skipped duplicates: {skipped}")


if __name__ == "__main__":
    main()
