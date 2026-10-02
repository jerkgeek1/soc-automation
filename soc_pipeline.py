from parsers.alert_parser import parse_alert
from detection.triage import assess_severity


sample_alert = {
    "timestamp": "2026-09-25T18:47:17.459",
    "agent": {
        "id": "001",
        "name": "windows-laptop"
    },
    "rule": {
        "id": "60122",
        "level": 5,
        "description": "Logon Failure - Unknown user or bad password"
    },
    "data": {
        "win": {
            "system": {
                "eventID": "4625"
            },
            "eventdata": {
                "targetUserName": "hp",
                "ipAddress": "127.0.0.1",
                "logonType": "2"
            }
        }
    }
}


# Step 1: Parse the raw alert
parsed_alert = parse_alert(sample_alert)

# Step 2: Assess severity
severity = assess_severity(parsed_alert)

# Step 3: Display SOC investigation summary
print("\n=== SOC AUTOMATION PIPELINE ===")

print(f"Timestamp: {parsed_alert['timestamp']}")
print(f"Agent: {parsed_alert['agent_name']}")
print(f"Event ID: {parsed_alert['event_id']}")
print(f"Rule: {parsed_alert['rule_id']}")
print(f"Description: {parsed_alert['rule_description']}")
print(f"Username: {parsed_alert['username']}")
print(f"Source IP: {parsed_alert['source_ip']}")
print(f"Logon Type: {parsed_alert['logon_type']}")
print(f"Initial Severity: {severity}")

print("\nAnalysis:")
print(
    "A Windows failed authentication event was detected. "
    "The current lab triage rules classify this alert as LOW severity."
)
