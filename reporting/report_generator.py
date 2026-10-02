import json
from pathlib import Path


def generate_report(incident):
    """
    Generate a clean Markdown SOC incident report.
    """

    enrichment = incident.get("ip_enrichment", {})
    recommendation = incident.get("response_recommendation", {})

    report = f"""# SOC INCIDENT REPORT

## Incident Overview

- **Incident ID:** {incident.get("incident_id")}
- **Severity:** {incident.get("severity")}
- **Status:** {incident.get("status")}
- **Created At:** {incident.get("created_at")}

## Detection

**Type:** {incident.get("detection_type")}

## Source Information

- **Source IP:** {incident.get("source_ip")}
- **IP Type:** {enrichment.get("type")}
- **Private IP:** {enrichment.get("is_private")}
- **Loopback:** {enrichment.get("is_loopback")}

## Authentication Activity

- **Username:** {incident.get("username")}
- **Failed Attempts:** {incident.get("failed_attempts")}
- **Detection Window:** {incident.get("window_start")}

## Analyst Assessment

{incident.get("analyst_assessment")}

## Recommended Response

- **Action:** {recommendation.get("action")}
- **Automation:** {recommendation.get("automation")}
- **Reason:** {recommendation.get("reason")}

## Analyst Notes

"""

    notes = incident.get("analyst_notes", [])

    if notes:
        for note in notes:
            report += f"- **{note.get('timestamp')}** — {note.get('note')}\n"
    else:
        report += "No analyst notes recorded.\n"

    report += "\n## Incident Timeline\n\n"

    timeline = incident.get("timeline", [])

    if timeline:
        for event in timeline:
            report += (
                f"- **{event.get('timestamp')}** — "
                f"{event.get('from_status')} → {event.get('to_status')}\n"
            )
    else:
        report += "No status changes recorded.\n"

    return report


def save_report(incident):
    """
    Save the incident report as a Markdown file.
    """

    report = generate_report(incident)

    report_dir = Path("incidents/reports")
    report_dir.mkdir(parents=True, exist_ok=True)

    file_path = report_dir / f"{incident['incident_id']}.md"

    with open(file_path, "w") as file:
        file.write(report)

    return file_path


def load_incident(incident_id):
    """
    Load an incident JSON file.
    """

    file_path = Path("incidents") / f"{incident_id}.json"

    if not file_path.exists():
        return None

    with open(file_path, "r") as file:
        return json.load(file)


if __name__ == "__main__":

    incident_id = input("Enter Incident ID: ")

    incident = load_incident(incident_id)

    if not incident:
        print("Incident not found.")
    else:
        report_path = save_report(incident)
        print(f"Report generated: {report_path}")
