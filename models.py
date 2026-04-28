# FEATURE ADDED: MTTD / MTTR Metrics
# FEATURE ADDED: Response Playbook Checklist

from datetime import datetime

from database import db


def now_string():
    """Return a second-precision local timestamp for SOC events."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def now_iso_string():
    """Return a second-precision local ISO timestamp for audit-style records."""
    return datetime.now().replace(microsecond=0).isoformat()


class Alert(db.Model):
    """Persistent SOC alert record used by the triage console."""
    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.String(40), unique=True, nullable=False, index=True)
    timestamp = db.Column(db.String(19), nullable=False, index=True)
    source_ip = db.Column(db.String(64), nullable=False, index=True)
    dest_ip = db.Column(db.String(64), nullable=False, index=True)
    alert_type = db.Column(db.String(80), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, index=True)
    raw_log = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(30), nullable=False, default="new", index=True)
    analyst_notes = db.Column(db.Text, default="")
    investigation_summary = db.Column(db.Text, default="")
    mitre_tactic = db.Column(db.String(120), default="")
    mitre_technique = db.Column(db.String(160), default="")
    mitre_description = db.Column(db.Text, default="")
    reputation_result = db.Column(db.Text, default="")
    reputation_score = db.Column(db.Integer, default=0)
    created_at = db.Column(db.String(19), default=now_string)
    updated_at = db.Column(db.String(19), default=now_string)
    closed_at = db.Column(db.String(19), nullable=True)

    def to_dict(self):
        """Serialize an alert for API responses."""
        return {
            "id": self.id,
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "raw_log": self.raw_log,
            "status": self.status,
            "analyst_notes": self.analyst_notes or "",
            "investigation_summary": self.investigation_summary or "",
            "mitre_tactic": self.mitre_tactic or "",
            "mitre_technique": self.mitre_technique or "",
            "mitre_description": self.mitre_description or "",
            "reputation_result": self.reputation_result or "",
            "reputation_score": self.reputation_score or 0,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "closed_at": self.closed_at,
        }


class TimelineEvent(db.Model):
    """Timeline event attached to an alert investigation."""
    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.String(40), nullable=False, index=True)
    event_name = db.Column(db.String(120), nullable=False)
    event_description = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.String(19), default=now_string, index=True)

    def to_dict(self):
        """Serialize a timeline event for API responses."""
        return {
            "id": self.id,
            "alert_id": self.alert_id,
            "event_name": self.event_name,
            "event_description": self.event_description,
            "timestamp": self.timestamp,
        }


class StatusChange(db.Model):
    """Status transition audit record for MTTD and MTTR calculations."""
    __tablename__ = "status_changes"

    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.String(40), nullable=False, index=True)
    old_status = db.Column(db.String(30), nullable=False)
    new_status = db.Column(db.String(30), nullable=False, index=True)
    changed_at = db.Column(db.String(24), default=now_iso_string, index=True)

    def to_dict(self):
        """Serialize a status transition for reporting."""
        return {
            "id": self.id,
            "alert_id": self.alert_id,
            "old_status": self.old_status,
            "new_status": self.new_status,
            "changed_at": self.changed_at,
        }


class PlaybookProgress(db.Model):
    """Per-alert incident response playbook progress state."""
    __tablename__ = "playbook_progress"

    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.String(40), nullable=False, index=True)
    step_index = db.Column(db.Integer, nullable=False)
    completed = db.Column(db.Integer, default=0)
    completed_at = db.Column(db.String(24), nullable=True)

    __table_args__ = (db.UniqueConstraint("alert_id", "step_index", name="uq_playbook_alert_step"),)

    def to_dict(self):
        """Serialize one playbook step state."""
        return {
            "id": self.id,
            "alert_id": self.alert_id,
            "step_index": self.step_index,
            "completed": bool(self.completed),
            "completed_at": self.completed_at,
        }
