from enrichment.ip_enrichment import enrich_ip
from collectors.wazuh_indexer import search_alerts
from parsers.alert_parser import parse_alert
from detection.time_window import detect_time_window
from reporting.incident import create_incident, save_incident
import getpass


print("=== SOC LIVE ALERT PIPELINE ===")

username = input("Indexer username: ")
password = getpass.getpass("Indexer password: ")

result = search_alerts(username, password)

alerts = []

for hit in result["hits"]["hits"]:
    parsed = parse_alert(hit["_source"])
    alerts.append(parsed)

print(f"\nCollected {len(alerts)} Windows 4625 alerts.")

print("\n=== TIME-WINDOW DETECTION ===")

detections = detect_time_window(alerts)

for detection in detections:
    ip_info = enrich_ip(detection["source_ip"])
    print(
        f"Source IP: {detection['source_ip']} | "
        f"Username: {detection['username']} | "
        f"Failures: {detection['failed_attempts']} | "
        f"Severity: {detection['severity']}"
    )

    if detection["severity"] in ["MEDIUM", "HIGH"]:
        incident = create_incident(detection)
        file_path = save_incident(incident)

        enrichment = incident["ip_enrichment"]

        print("=== IP ENRICHMENT ===")
        print(f"IP: {enrichment['ip']}")
        print(f"Type: {enrichment['type']}")
        print(f"Private: {enrichment['is_private']}")
        print(f"Loopback: {enrichment['is_loopback']}")


        print(f"Incident created: {incident['incident_id']}")
        print(f"Incident file: {file_path}")

