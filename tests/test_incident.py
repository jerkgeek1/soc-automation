
import json

from reporting.incident import create_incident, save_incident
from reporting.incident import update_incident_status, add_analyst_note
from enrichment.ip_enrichment import enrich_ip


def test_incident_creation(tmp_path, monkeypatch):

    detection = {
        "source_ip": "10.0.0.50",
        "username": "testuser",
        "failed_attempts": 5,
        "severity": "HIGH",
        "window_start": "2026-10-02T10:00:00+00:00"
    }

    incident = create_incident(detection)

    assert incident["severity"] == "HIGH"
    assert incident["source_ip"] == "10.0.0.50"
    assert incident["username"] == "testuser"
    assert incident["failed_attempts"] == 5
    assert incident["status"] == "OPEN"


def test_ip_enrichment():

    result = enrich_ip("10.0.0.50")

    assert result["type"] == "PRIVATE"
    assert result["is_private"] is True
    assert result["is_loopback"] is False


def test_incident_status_and_note(tmp_path, monkeypatch):

    import reporting.incident as incident_module

    monkeypatch.setattr(
        incident_module,
        "INCIDENT_DIR",
        tmp_path
    )

    incident = {
        "incident_id": "INC-TEST1234",
        "status": "OPEN",
        "severity": "MEDIUM"
    }

    file_path = tmp_path / "INC-TEST1234.json"

    with open(file_path, "w") as file:
        json.dump(incident, file)

    assert update_incident_status(
        "INC-TEST1234",
        "INVESTIGATING"
    ) is True

    assert add_analyst_note(
        "INC-TEST1234",
        "Test analyst note."
    ) is True

    with open(file_path, "r") as file:
        updated = json.load(file)

    assert updated["status"] == "INVESTIGATING"
    assert len(updated["timeline"]) == 1
    assert len(updated["analyst_notes"]) == 1
