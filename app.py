from dotenv import load_dotenv

load_dotenv()

# FEATURE ADDED: MTTD / MTTR Metrics
# FEATURE ADDED: Alert Correlation Engine
# FEATURE ADDED: Shift Handoff Report
# FEATURE ADDED: Response Playbook Checklist
# FEATURE ADDED: Sigma Rule Generator

import json
import os
import re
import uuid
from datetime import datetime, timedelta, timezone

import requests
from flask import Flask, jsonify, render_template, request
from sqlalchemy import func, or_

from database import db, init_database
from generate_alerts import build_alert
from mitre_rules import MITRE_RULES
from models import Alert, PlaybookProgress, StatusChange, TimelineEvent, now_iso_string, now_string
from playbooks import PLAYBOOKS


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///sentinelops.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "sentinelops-local-dev")
init_database(app)

VALID_STATUSES = {"new", "investigating", "escalated", "closed"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}
SIGMA_LOGSOURCES = {
    "brute_force": {"category": "authentication", "product": "windows"},
    "port_scan": {"category": "network", "product": "zeek"},
    "phishing_email": {"category": "email", "product": "exchange"},
    "malware_download": {"category": "process_creation", "product": "windows"},
    "suspicious_login": {"category": "authentication", "product": "windows"},
    "powershell_execution": {"category": "process_creation", "product": "windows"},
    "command_and_control": {"category": "network", "product": "firewall"},
    "web_attack": {"category": "webserver", "product": "apache"},
    "lateral_movement": {"category": "network", "product": "windows"},
    "dns_tunneling": {"category": "dns", "product": "zeek"},
    "privilege_escalation": {"category": "process_creation", "product": "windows"},
    "data_exfiltration": {"category": "network", "product": "firewall"},
}
COMMON_SIGMA_WORDS = {
    "the",
    "and",
    "from",
    "with",
    "action",
    "src",
    "dst",
    "user",
    "host",
    "alert",
    "possible",
    "observed",
    "blocked",
    "monitored",
    "safe",
    "simulated",
}


def add_timeline(alert_id, event_name, event_description):
    """Persist one timeline event for an alert investigation."""
    event = TimelineEvent(alert_id=alert_id, event_name=event_name, event_description=event_description, timestamp=now_string())
    db.session.add(event)
    db.session.commit()
    return event


def add_timeline_pending(alert_id, event_name, event_description):
    """Stage one timeline event for commit with a larger transaction."""
    event = TimelineEvent(alert_id=alert_id, event_name=event_name, event_description=event_description, timestamp=now_string())
    db.session.add(event)
    return event


def parse_datetime(value):
    """Parse local and ISO timestamps used by SentinelOps records."""
    if not value:
        return None
    cleaned = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        parsed = datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S")
    if parsed.tzinfo:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def format_duration(seconds):
    """Format seconds as HH:MM:SS."""
    seconds = max(int(seconds or 0), 0)
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    remaining = seconds % 60
    return f"{hours:02d}:{minutes:02d}:{remaining:02d}"


def first_status_change(alert_id, status):
    """Return the first status change row for an alert and target status."""
    return (
        StatusChange.query.filter_by(alert_id=alert_id, new_status=status)
        .order_by(StatusChange.changed_at.asc())
        .first()
    )


def average_mttd_mttr(alerts=None):
    """Calculate MTTD and MTTR seconds for all supplied alerts."""
    scoped_alerts = alerts if alerts is not None else Alert.query.all()
    mttd_values = []
    mttr_values = []
    for alert in scoped_alerts:
        first_investigating = first_status_change(alert.alert_id, "investigating")
        if first_investigating:
            detected_at = parse_datetime(first_investigating.changed_at)
            received_at = parse_datetime(alert.timestamp)
            if detected_at and received_at and detected_at >= received_at:
                mttd_values.append((detected_at - received_at).total_seconds())
        first_closed = first_status_change(alert.alert_id, "closed")
        if first_investigating and first_closed:
            investigated_at = parse_datetime(first_investigating.changed_at)
            closed_at = parse_datetime(first_closed.changed_at)
            if investigated_at and closed_at and closed_at >= investigated_at:
                mttr_values.append((closed_at - investigated_at).total_seconds())
    mttd_seconds = int(sum(mttd_values) / len(mttd_values)) if mttd_values else 0
    mttr_seconds = int(sum(mttr_values) / len(mttr_values)) if mttr_values else 0
    return {
        "mttd_seconds": mttd_seconds,
        "mttr_seconds": mttr_seconds,
        "mttd_formatted": format_duration(mttd_seconds),
        "mttr_formatted": format_duration(mttr_seconds),
    }


def alert_display_name(alert):
    """Return a human-readable alert title for reporting and Sigma output."""
    return alert.alert_type.replace("_", " ").title()


def tactic_slug(mitre_tactic):
    """Convert a MITRE tactic display string into a Sigma tag slug."""
    without_id = re.sub(r"TA\d+\s*", "", mitre_tactic or "").strip()
    slug = re.sub(r"[^a-z0-9]+", "_", without_id.lower()).strip("_")
    return slug or "unclassified"


def technique_id(alert):
    """Extract a MITRE technique ID from saved mapping or local rule."""
    if alert.mitre_technique:
        match = re.search(r"T\d+(?:\.\d+)?", alert.mitre_technique)
        if match:
            return match.group(0).lower()
    rule = MITRE_RULES.get(alert.alert_type, {})
    return str(rule.get("technique_id", "t0000")).lower()


def sigma_keywords(raw_log):
    """Extract 2-3 meaningful Sigma keyword tokens from a raw log line."""
    tokens = re.findall(r"[A-Za-z][A-Za-z0-9_-]{3,}", raw_log or "")
    keywords = []
    for token in tokens:
        lowered = token.lower()
        if lowered in COMMON_SIGMA_WORDS or re.match(r"^\d+\.\d+\.\d+\.\d+$", lowered):
            continue
        if lowered not in keywords:
            keywords.append(lowered)
        if len(keywords) == 3:
            break
    return keywords or ["suspicious", "security", "alert"]


def seconds_between(start_value, end_value):
    """Return positive seconds between two SentinelOps timestamp strings."""
    start = parse_datetime(start_value)
    end = parse_datetime(end_value)
    if not start or not end or end < start:
        return None
    return int((end - start).total_seconds())


def get_alert_or_404(alert_id):
    """Fetch an alert by external alert ID or return None."""
    return Alert.query.filter_by(alert_id=alert_id).first()


def alert_from_payload(payload):
    """Create an Alert model from generated or ingested alert JSON."""
    return Alert(
        alert_id=payload["alert_id"],
        timestamp=payload["timestamp"],
        source_ip=payload["source_ip"],
        dest_ip=payload["dest_ip"],
        alert_type=payload["alert_type"],
        severity=payload["severity"],
        raw_log=payload["raw_log"],
        status=payload.get("status", "new"),
        created_at=now_string(),
        updated_at=now_string(),
    )


def next_alert_id():
    """Find the next available ALERT-2026 identifier."""
    next_index = Alert.query.count() + 1
    candidate = f"ALERT-2026-{next_index:04d}"
    while Alert.query.filter_by(alert_id=candidate).first():
        next_index += 1
        candidate = f"ALERT-2026-{next_index:04d}"
    return candidate


def reputation_score_from_vt(result):
    """Convert a VirusTotal response into a 0-100 risk score."""
    stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    return min(100, malicious * 15 + suspicious * 5)


def distribution(column, allowed_values):
    """Return a complete count dictionary for a SQLAlchemy column."""
    counts = {value: 0 for value in allowed_values}
    rows = db.session.query(column, func.count(Alert.id)).group_by(column).all()
    for key, count in rows:
        counts[key] = count
    return counts


@app.after_request
def no_cache(response):
    """Keep API responses fresh for live monitoring behavior."""
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/")
def index():
    """Render the SentinelOps single-page SOC console."""
    return render_template("index.html")


@app.route("/api/alerts")
def api_alerts():
    """Return alerts with optional severity, status, type, and search filters."""
    query = Alert.query
    severity = request.args.get("severity", "").strip().lower()
    status = request.args.get("status", "").strip().lower()
    alert_type = request.args.get("alert_type", "").strip()
    search = request.args.get("search", "").strip()

    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    if alert_type:
        query = query.filter(Alert.alert_type == alert_type)
    if search:
        like = f"%{search}%"
        query = query.filter(or_(Alert.alert_id.ilike(like), Alert.source_ip.ilike(like), Alert.dest_ip.ilike(like)))

    alerts = query.order_by(Alert.timestamp.desc()).all()
    return jsonify({"alerts": [alert.to_dict() for alert in alerts]})


@app.route("/api/alerts/<alert_id>")
def api_alert_detail(alert_id):
    """Return full alert details for one alert."""
    alert = get_alert_or_404(alert_id)
    if not alert:
        return jsonify({"error": "alert_not_found"}), 404
    return jsonify(alert.to_dict())


@app.route("/api/classify/<alert_id>", methods=["POST"])
def api_classify(alert_id):
    """Classify an alert using the local MITRE ATT&CK mapping table."""
    alert = get_alert_or_404(alert_id)
    if not alert:
        return jsonify({"error": "alert_not_found"}), 404
    rule = MITRE_RULES.get(alert.alert_type)
    if not rule:
        return jsonify({"error": "mitre_rule_not_found"}), 404
    alert.mitre_tactic = rule["tactic"]
    alert.mitre_technique = f'{rule["technique_id"]} {rule["technique_name"]}'
    alert.mitre_description = rule["description"]
    alert.updated_at = now_string()
    db.session.commit()
    add_timeline(alert.alert_id, "MITRE classification completed", f'Mapped to {rule["tactic"]} / {rule["technique_id"]} {rule["technique_name"]}.')
    return jsonify({"message": "MITRE classification saved.", "alert": alert.to_dict()})


@app.route("/api/enrich/<alert_id>", methods=["POST"])
def api_enrich(alert_id):
    """Enrich the source IP with VirusTotal or return a professional no-key message."""
    alert = get_alert_or_404(alert_id)
    if not alert:
        return jsonify({"error": "alert_not_found"}), 404

    vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if not vt_key or vt_key == "your_key_here":
        message = "VirusTotal API key not configured. Create a .env file and add VIRUSTOTAL_API_KEY=your_key_here to enable live IP reputation checks."
        alert.reputation_result = message
        alert.reputation_score = 0
        alert.updated_at = now_string()
        db.session.commit()
        add_timeline(alert.alert_id, "IP enrichment completed", message)
        return jsonify({"status": "no_key", "message": message, "alert": alert.to_dict()})

    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip-addresses/{alert.source_ip}",
            headers={"x-apikey": vt_key},
            timeout=8,
        )
        if not response.ok:
            raise requests.RequestException(f"VirusTotal returned status {response.status_code}")
        result = response.json()
        attributes = result.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        total_engines = malicious + suspicious + harmless + undetected
        reputation_score = int((malicious / max(total_engines, 1)) * 100)
        country = attributes.get("country", "Unknown") or "Unknown"
        saved_result = {
            "source_ip": alert.source_ip,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "reputation_score": reputation_score,
            "country": country,
            "raw": result,
        }
        alert.reputation_result = json.dumps(saved_result)
        alert.reputation_score = reputation_score
        alert.updated_at = now_string()
        db.session.commit()
        add_timeline(alert.alert_id, "IP enrichment completed", "Live VirusTotal IP reputation check completed.")
        return jsonify(
            {
                "status": "success",
                "source_ip": alert.source_ip,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "reputation_score": reputation_score,
                "country": country,
                "alert": alert.to_dict(),
            }
        )
    except requests.RequestException as exc:
        message = f"VirusTotal enrichment unavailable: {exc}"
        alert.reputation_result = message
        alert.reputation_score = 0
        alert.updated_at = now_string()
        db.session.commit()
        add_timeline(alert.alert_id, "IP enrichment completed", message)
        return jsonify({"status": "error", "message": message, "alert": alert.to_dict()}), 502


@app.route("/api/update_status/<alert_id>", methods=["POST"])
def api_update_status(alert_id):
    """Update alert status and close timestamp when appropriate."""
    alert = get_alert_or_404(alert_id)
    if not alert:
        return jsonify({"error": "alert_not_found"}), 404
    payload = request.get_json(silent=True) or {}
    status = str(payload.get("status", "")).strip().lower()
    if status not in VALID_STATUSES:
        return jsonify({"error": "invalid_status"}), 400
    old_status = alert.status
    change = StatusChange(alert_id=alert.alert_id, old_status=old_status, new_status=status, changed_at=now_iso_string())
    db.session.add(change)
    alert.status = status
    alert.updated_at = now_string()
    if status == "closed":
        alert.closed_at = now_string()
    add_timeline_pending(alert.alert_id, "case closed" if status == "closed" else "status updated", f"Status changed from {old_status} to {status}.")
    db.session.commit()
    return jsonify({"message": "Status updated.", "alert": alert.to_dict()})


@app.route("/api/update_notes/<alert_id>", methods=["POST"])
def api_update_notes(alert_id):
    """Save analyst notes and investigation summary."""
    alert = get_alert_or_404(alert_id)
    if not alert:
        return jsonify({"error": "alert_not_found"}), 404
    payload = request.get_json(silent=True) or {}
    alert.analyst_notes = str(payload.get("analyst_notes", ""))[:8000]
    alert.investigation_summary = str(payload.get("investigation_summary", ""))[:8000]
    alert.updated_at = now_string()
    db.session.commit()
    add_timeline(alert.alert_id, "analyst notes saved", "Analyst notes and investigation summary were updated.")
    return jsonify({"message": "Notes saved.", "alert": alert.to_dict()})


@app.route("/api/stats")
def api_stats():
    """Return dashboard statistics and reporting distributions."""
    today = datetime.now().strftime("%Y-%m-%d")
    total_alerts = Alert.query.count()
    critical_alerts = Alert.query.filter_by(severity="critical").count()
    open_investigations = Alert.query.filter(Alert.status.in_(["new", "investigating", "escalated"])).count()
    closed_today = Alert.query.filter(Alert.closed_at.like(f"{today}%")).count()
    top_ips = (
        db.session.query(Alert.source_ip, func.count(Alert.id).label("count"))
        .group_by(Alert.source_ip)
        .order_by(func.count(Alert.id).desc())
        .limit(5)
        .all()
    )
    by_type = db.session.query(Alert.alert_type, func.count(Alert.id)).group_by(Alert.alert_type).all()
    tactic_distribution = db.session.query(Alert.mitre_tactic, func.count(Alert.id)).filter(Alert.mitre_tactic != "").group_by(Alert.mitre_tactic).all()
    latest = Alert.query.order_by(Alert.timestamp.desc()).limit(10).all()
    time_metrics = average_mttd_mttr()
    return jsonify(
        {
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "open_investigations": open_investigations,
            "closed_today": closed_today,
            "mttd_seconds": time_metrics["mttd_seconds"],
            "mttr_seconds": time_metrics["mttr_seconds"],
            "mttd_formatted": time_metrics["mttd_formatted"],
            "mttr_formatted": time_metrics["mttr_formatted"],
            "count_per_severity": distribution(Alert.severity, ["low", "medium", "high", "critical"]),
            "count_per_status": distribution(Alert.status, ["new", "investigating", "escalated", "closed"]),
            "top_5_source_ips": [{"source_ip": ip, "count": count} for ip, count in top_ips],
            "alert_count_by_type": {key: count for key, count in by_type},
            "mitre_tactic_distribution": {key or "Unclassified": count for key, count in tactic_distribution},
            "latest_10_alerts": [alert.to_dict() for alert in latest],
        }
    )


@app.route("/api/timeline/<alert_id>")
def api_timeline(alert_id):
    """Return timeline events for one alert."""
    alert = get_alert_or_404(alert_id)
    if not alert:
        return jsonify({"error": "alert_not_found"}), 404
    events = TimelineEvent.query.filter_by(alert_id=alert_id).order_by(TimelineEvent.timestamp.asc()).all()
    return jsonify({"timeline": [event.to_dict() for event in events]})


@app.route("/api/export/<alert_id>")
def api_export(alert_id):
    """Return an investigation export as JSON."""
    alert = get_alert_or_404(alert_id)
    if not alert:
        return jsonify({"error": "alert_not_found"}), 404
    events = TimelineEvent.query.filter_by(alert_id=alert_id).order_by(TimelineEvent.timestamp.asc()).all()
    return jsonify(
        {
            "alert_metadata": alert.to_dict(),
            "raw_log": alert.raw_log,
            "mitre_mapping": {
                "tactic": alert.mitre_tactic,
                "technique": alert.mitre_technique,
                "description": alert.mitre_description,
            },
            "reputation_result": alert.reputation_result,
            "analyst_notes": alert.analyst_notes,
            "investigation_summary": alert.investigation_summary,
            "status": alert.status,
            "timeline_summary": [event.to_dict() for event in events],
        }
    )


def correlated_alert_payload(alert, reason):
    """Serialize an alert and attach the primary correlation reason."""
    payload = alert.to_dict()
    payload["correlation_reason"] = reason
    return payload


def collect_correlated_alerts(alert):
    """Find related alerts by source, MITRE tactic, and alert type windows."""
    now = datetime.now()
    buckets = [
        ("Same source IP", "source_ip", alert.source_ip, now - timedelta(hours=24)),
        ("Same MITRE tactic", "mitre_tactic", alert.mitre_tactic, now - timedelta(hours=12)),
        ("Same alert type", "alert_type", alert.alert_type, now - timedelta(hours=6)),
    ]
    correlated = {}
    for reason, field, value, since in buckets:
        if not value:
            continue
        candidates = Alert.query.filter(getattr(Alert, field) == value, Alert.alert_id != alert.alert_id).all()
        for candidate in candidates:
            candidate_time = parse_datetime(candidate.timestamp)
            if candidate_time and candidate_time >= since and candidate.alert_id not in correlated:
                correlated[candidate.alert_id] = correlated_alert_payload(candidate, reason)
    same_source_count = sum(1 for item in correlated.values() if item["source_ip"] == alert.source_ip)
    ordered = sorted(correlated.values(), key=lambda item: item["timestamp"], reverse=True)
    return ordered, same_source_count >= 3


@app.route("/api/alerts/correlated/")
@app.route("/api/alerts/correlated/<alert_id>")
def api_correlated_alerts(alert_id=None):
    """Return alerts correlated to the active investigation."""
    resolved_alert_id = alert_id or request.args.get("alert_id", "").strip()
    if not resolved_alert_id:
        return jsonify({"error": "alert_id_required"}), 400
    alert = get_alert_or_404(resolved_alert_id)
    if not alert:
        return jsonify({"error": "alert_not_found"}), 404
    correlated, coordinated_attack = collect_correlated_alerts(alert)
    return jsonify({"correlated": correlated, "coordinated_attack": coordinated_attack, "total": len(correlated)})


@app.route("/api/reports/shift")
def api_shift_report():
    """Compile an eight-hour analyst shift handoff report."""
    now = datetime.now()
    shift_start = now - timedelta(hours=8)
    alerts = [alert for alert in Alert.query.all() if (parse_datetime(alert.timestamp) or datetime.min) >= shift_start]
    severity_counts = {severity: 0 for severity in ["critical", "high", "medium", "low"]}
    status_counts = {status: 0 for status in ["new", "investigating", "escalated", "closed"]}
    tactic_counts = {}
    critical_open = []
    closed_this_shift = 0
    for alert in alerts:
        if alert.severity in severity_counts:
            severity_counts[alert.severity] += 1
        if alert.status in status_counts:
            status_counts[alert.status] += 1
        tactic = alert.mitre_tactic or "Unclassified"
        tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        if alert.severity in {"critical", "high"} and alert.status in {"new", "investigating"}:
            critical_open.append(
                {
                    "alert_id": alert.alert_id,
                    "alert_type": alert.alert_type,
                    "source_ip": alert.source_ip,
                    "timestamp": alert.timestamp,
                }
            )
        if alert.closed_at and (parse_datetime(alert.closed_at) or datetime.min) >= shift_start:
            closed_this_shift += 1
    shift_metrics = average_mttd_mttr(alerts)
    top_mitre = [
        {"tactic": tactic, "count": count}
        for tactic, count in sorted(tactic_counts.items(), key=lambda item: item[1], reverse=True)[:3]
    ]
    return jsonify(
        {
            "report_generated_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
            "analyst": "Rewantth Babh Vadlakonda",
            "period": "Last 8 hours",
            "total_alerts": len(alerts),
            "by_severity": severity_counts,
            "by_status": status_counts,
            "top_mitre_tactics": top_mitre,
            "critical_open": critical_open,
            "closed_this_shift": closed_this_shift,
            "mttd_this_shift": shift_metrics["mttd_formatted"],
            "mttr_this_shift": shift_metrics["mttr_formatted"],
        }
    )


def playbook_response(alert):
    """Build playbook progress payload for an alert type."""
    steps = PLAYBOOKS.get(alert.alert_type, [])
    progress_rows = {
        row.step_index: row
        for row in PlaybookProgress.query.filter_by(alert_id=alert.alert_id).all()
    }
    rendered_steps = []
    completed_count = 0
    for index, text in enumerate(steps, start=1):
        row = progress_rows.get(index)
        completed = bool(row.completed) if row else False
        if completed:
            completed_count += 1
        rendered_steps.append(
            {
                "index": index,
                "text": text,
                "completed": completed,
                "completed_at": row.completed_at if row else None,
            }
        )
    progress_percent = round((completed_count / len(steps)) * 100) if steps else 0
    return {
        "steps": rendered_steps,
        "completed_count": completed_count,
        "total_steps": len(steps),
        "progress_percent": progress_percent,
        "complete": bool(steps) and completed_count == len(steps),
    }


@app.route("/api/playbook/<alert_id>")
def api_playbook(alert_id):
    """Return response playbook steps and per-alert completion state."""
    alert = get_alert_or_404(alert_id)
    if not alert:
        return jsonify({"error": "alert_not_found"}), 404
    return jsonify(playbook_response(alert))


@app.route("/api/playbook/<alert_id>/<int:step_index>", methods=["POST"])
def api_toggle_playbook_step(alert_id, step_index):
    """Toggle one incident response playbook step."""
    alert = get_alert_or_404(alert_id)
    if not alert:
        return jsonify({"error": "alert_not_found"}), 404
    steps = PLAYBOOKS.get(alert.alert_type, [])
    if step_index < 1 or step_index > len(steps):
        return jsonify({"error": "invalid_step"}), 400
    progress = PlaybookProgress.query.filter_by(alert_id=alert.alert_id, step_index=step_index).first()
    if not progress:
        progress = PlaybookProgress(alert_id=alert.alert_id, step_index=step_index, completed=0)
        db.session.add(progress)
    progress.completed = 0 if progress.completed else 1
    progress.completed_at = now_iso_string() if progress.completed else None
    add_timeline_pending(
        alert.alert_id,
        "playbook step updated",
        f"Response playbook step {step_index} marked {'complete' if progress.completed else 'incomplete'}.",
    )
    db.session.commit()
    payload = playbook_response(alert)
    return jsonify(
        {
            "step": {
                "index": step_index,
                "text": steps[step_index - 1],
                "completed": bool(progress.completed),
                "completed_at": progress.completed_at,
            },
            "progress_percent": payload["progress_percent"],
            "complete": payload["complete"],
            "playbook": payload,
        }
    )


@app.route("/api/sigma/<alert_id>")
def api_sigma(alert_id):
    """Generate a Sigma-style detection rule from a selected alert."""
    alert = get_alert_or_404(alert_id)
    if not alert:
        return jsonify({"error": "alert_not_found"}), 404
    rule = MITRE_RULES.get(alert.alert_type, {})
    tactic = alert.mitre_tactic or rule.get("tactic", "Unclassified")
    technique = technique_id(alert)
    logsource = SIGMA_LOGSOURCES.get(alert.alert_type, {"category": "generic", "product": "security"})
    keywords = sigma_keywords(alert.raw_log)
    yaml_lines = [
        f"title: {alert_display_name(alert)}",
        f"id: {uuid.uuid4()}",
        "status: experimental",
        f"description: \"Detects {alert_display_name(alert)} activity. Auto-generated by SentinelOps for educational demonstration.\"",
        "references: []",
        "author: Rewantth Babh Vadlakonda",
        f"date: {datetime.now().strftime('%Y/%m/%d')}",
        "tags:",
        f"  - attack.{tactic_slug(tactic)}",
        f"  - attack.{technique}",
        "logsource:",
        f"  category: {logsource['category']}",
        f"  product: {logsource['product']}",
        "detection:",
        "  keywords:",
    ]
    yaml_lines.extend([f"    - {keyword}" for keyword in keywords])
    yaml_lines.extend(
        [
            "  condition: keywords",
            "falsepositives:",
            "  - Legitimate administrative activity",
            "  - Authorized security testing",
            f"level: {alert.severity}",
        ]
    )
    return jsonify({"alert_id": alert.alert_id, "sigma_yaml": "\n".join(yaml_lines), "generated_at": now_iso_string()})


@app.route("/api/simulate_alert", methods=["POST"])
def api_simulate_alert():
    """Create one new safe simulated alert and return it as JSON."""
    alert_id = next_alert_id()
    payload = build_alert(Alert.query.count() + 1, timestamp=datetime.now(), alert_id=alert_id)
    alert = alert_from_payload(payload)
    db.session.add(alert)
    db.session.commit()
    add_timeline(alert.alert_id, "alert received", "New safe simulated alert ingested through live simulation mode.")
    return jsonify({"message": "Simulated alert generated.", "alert": alert.to_dict()}), 201


if __name__ == "__main__":
    app.run(debug=True, port=int(os.getenv("PORT", "5000")))
