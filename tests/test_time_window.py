from detection.time_window import detect_time_window


test_alerts = [
    {
        "event_id": "4625",
        "username": "hp",
        "source_ip": "10.0.0.50",
        "timestamp": "2026-09-25T18:00:00"
    },
    {
        "event_id": "4625",
        "username": "hp",
        "source_ip": "10.0.0.50",
        "timestamp": "2026-09-25T18:01:00"
    },
    {
        "event_id": "4625",
        "username": "hp",
        "source_ip": "10.0.0.50",
        "timestamp": "2026-09-25T18:02:00"
    },
    {
        "event_id": "4625",
        "username": "hp",
        "source_ip": "10.0.0.50",
        "timestamp": "2026-09-25T18:03:00"
    },
    {
        "event_id": "4625",
        "username": "hp",
        "source_ip": "10.0.0.50",
        "timestamp": "2026-09-25T18:04:00"
    }
]


results = detect_time_window(test_alerts)

print("=== TIME WINDOW TEST ===")

for result in results:
    print(
        f"Source IP: {result['source_ip']} | "
        f"Username: {result['username']} | "
        f"Failures: {result['failed_attempts']} | "
        f"Severity: {result['severity']}"
    )
