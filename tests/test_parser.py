from parsers.alert_parser import parse_alert


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


parsed = parse_alert(sample_alert)

print("=== SOC ALERT PARSER TEST ===")

for key, value in parsed.items():
    print(f"{key}: {value}")
