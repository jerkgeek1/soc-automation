from detection.correlation import correlate_failed_logins


test_alerts = [
    {"event_id": "4625", "username": "hp", "source_ip": "127.0.0.1"},
    {"event_id": "4625", "username": "hp", "source_ip": "127.0.0.1"},
    {"event_id": "4625", "username": "hp", "source_ip": "127.0.0.1"},
    {"event_id": "4625", "username": "hp", "source_ip": "127.0.0.1"},
    {"event_id": "4625", "username": "hp", "source_ip": "127.0.0.1"},

    {"event_id": "4625", "username": "admin", "source_ip": "10.0.0.5"},
]


results = correlate_failed_logins(test_alerts)

print("=== CORRELATION TEST ===")

for result in results:
    print(
        f"Source IP: {result['source_ip']} | "
        f"Username: {result['username']} | "
        f"Failures: {result['failed_attempts']} | "
        f"Severity: {result['severity']}"
    )
