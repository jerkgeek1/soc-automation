from detection.triage import assess_severity


test_alert = {
    "event_id": "4625",
    "rule_level": 5
}

severity = assess_severity(test_alert)

print("=== SOC TRIAGE TEST ===")
print(f"Event ID: {test_alert['event_id']}")
print(f"Wazuh Rule Level: {test_alert['rule_level']}")
print(f"Initial Severity: {severity}")
