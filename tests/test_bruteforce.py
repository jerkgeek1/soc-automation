from detection.bruteforce import detect_failed_login_pattern


test_alerts = [
    {"event_id": "4625", "username": "hp", "source_ip": "127.0.0.1"},
    {"event_id": "4625", "username": "hp", "source_ip": "127.0.0.1"},
    {"event_id": "4625", "username": "hp", "source_ip": "127.0.0.1"},
    {"event_id": "4625", "username": "hp", "source_ip": "127.0.0.1"},
    {"event_id": "4625", "username": "hp", "source_ip": "127.0.0.1"},
]


result = detect_failed_login_pattern(test_alerts)

print("=== BRUTE-FORCE DETECTION TEST ===")
print(f"Failed login events: {result['event_count']}")
print(f"Detected severity: {result['severity']}")
