from datetime import datetime
import uuid
import json
from pathlib import Path
from enrichment.ip_enrichment import enrich_ip
from response.recommendation import recommend_response

INCIDENT_DIR = Path("incidents")


def create_incident(detection):
    """
    Convert a detection result into a structured SOC incident.
    """
    response_recommendation = recommend_response({
    **detection,
    "ip_enrichment": enrich_ip(detection["source_ip"])
})
    incident = {
        "incident_id": f"INC-{uuid.uuid4().hex[:8].upper()}",
        "created_at": datetime.now().isoformat(),
        "status": "OPEN",
        "detection_type": "Windows Failed Login Pattern",
        "severity": detection["severity"],
        "source_ip": detection["source_ip"],
        "ip_enrichment": enrich_ip(detection["source_ip"]),
        "response_recommendation": response_recommendation,
        "analyst_assessment": (
          "Source is loopback/private. "
          "Investigate local authentication activity; "
          "do not treat as remote brute-force without additional evidence."
          if enrich_ip(detection["source_ip"])["is_loopback"]
          else
          "Source is not loopback. Investigate authentication activity "
          "and validate whether the source is authorized."
          ),
        "username": detection["username"],
        "failed_attempts": detection["failed_attempts"],
        "window_start": detection["window_start"],
        "recommended_action": (
            "Investigate authentication activity and validate "
            "whether the source is authorized."
        )
    }

    return incident


def save_incident(incident):
    """
    Save an incident as a JSON file.
    """

    INCIDENT_DIR.mkdir(exist_ok=True)

    file_path = INCIDENT_DIR / f"{incident['incident_id']}.json"

    with open(file_path, "w") as file:
        json.dump(incident, file, indent=4)

    return file_path

def update_incident_status(incident_id, new_status):
    """
    Update incident status and record the change
    in the incident timeline.
    """

    file_path = INCIDENT_DIR / f"{incident_id}.json"

    if not file_path.exists():
        return False

    with open(file_path, "r") as file:
        incident = json.load(file)

    allowed_statuses = {
        "OPEN",
        "INVESTIGATING",
        "RESOLVED",
        "FALSE_POSITIVE"
    }

    if new_status not in allowed_statuses:
        raise ValueError("Invalid incident status")

    old_status = incident.get("status")

    if "timeline" not in incident:
        incident["timeline"] = []

    incident["timeline"].append({
        "timestamp": datetime.now().isoformat(),
        "from_status": old_status,
        "to_status": new_status
    })

    incident["status"] = new_status

    with open(file_path, "w") as file:
        json.dump(incident, file, indent=4)

    return True

def add_analyst_note(incident_id, note):
    """
    Add an analyst note to an existing incident.
    """

    file_path = INCIDENT_DIR / f"{incident_id}.json"

    if not file_path.exists():
        return False

    with open(file_path, "r") as file:
        incident = json.load(file)

    if "analyst_notes" not in incident:
        incident["analyst_notes"] = []

    incident["analyst_notes"].append({
        "timestamp": datetime.now().isoformat(),
        "note": note
    })

    with open(file_path, "w") as file:
        json.dump(incident, file, indent=4)

    return True
