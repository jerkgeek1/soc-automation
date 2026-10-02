import requests
import getpass

from parsers.alert_parser import parse_alert

INDEXER_URL = "https://127.0.0.1:9201"

def search_alerts(username, password):
    url = f"{INDEXER_URL}/wazuh-alerts-4.x-*/_search"

    query = {
        "size": 5,
        "query": {
            "match": {
                "data.win.system.eventID": "4625"
            }
        },
        "sort": [
            {
                "timestamp": {
                    "order": "desc"
                }
            }
        ]
    }

    response = requests.post(
        url,
        auth=(username, password),
        json=query,
        verify=False,
        timeout=10
    )

    response.raise_for_status()

    return response.json()


if __name__ == "__main__":
    print("=== WAZUH INDEXER ALERT COLLECTOR ===")

    username = input("Indexer username: ")
    password = getpass.getpass("Indexer password: ")

    result = search_alerts(username, password)

    print("\n=== RECENT WINDOWS 4625 ALERTS ===")

    for hit in result["hits"]["hits"]:
        alert = hit["_source"]

        parsed = parse_alert(alert)

        print("\n--- PARSED ALERT ---")
        print(f"Timestamp: {parsed['timestamp']}")
        print(f"Agent: {parsed['agent_name']}")
        print(f"Event ID: {parsed['event_id']}")
        print(f"Username: {parsed['username']}")
        print(f"Source IP: {parsed['source_ip']}")
        print(f"Logon Type: {parsed['logon_type']}")
        print(f"Rule ID: {parsed['rule_id']}")
        print(f"Severity: {parsed['rule_level']}")

