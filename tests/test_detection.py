from detection.bruteforce import detect_failed_login_pattern
from detection.correlation import correlate_failed_logins
from detection.time_window import detect_time_window


def make_alert(timestamp, source_ip="10.0.0.50", username="testuser"):
    return {
        "timestamp": timestamp,
        "event_id": "4625",
        "source_ip": source_ip,
        "username": username,
    }


def test_bruteforce_detection():
    alerts = [
        make_alert("2026-10-02T10:00:00+00:00"),
        make_alert("2026-10-02T10:00:10+00:00"),
        make_alert("2026-10-02T10:00:20+00:00"),
        make_alert("2026-10-02T10:00:30+00:00"),
        make_alert("2026-10-02T10:00:40+00:00"),
    ]

    result = detect_failed_login_pattern(alerts)

    assert result["event_count"] == 5
    assert result["severity"] == "HIGH"


def test_correlation():
    alerts = [
        make_alert("2026-10-02T10:00:00+00:00"),
        make_alert("2026-10-02T10:00:10+00:00"),
        make_alert("2026-10-02T10:00:20+00:00"),
    ]

    result = correlate_failed_logins(alerts)

    assert len(result) == 1
    assert result[0]["source_ip"] == "10.0.0.50"
    assert result[0]["username"] == "testuser"
    assert result[0]["failed_attempts"] == 3
    assert result[0]["severity"] == "MEDIUM"


def test_time_window():
    alerts = [
        make_alert("2026-10-02T10:00:00+00:00"),
        make_alert("2026-10-02T10:01:00+00:00"),
        make_alert("2026-10-02T10:02:00+00:00"),
        make_alert("2026-10-02T10:03:00+00:00"),
        make_alert("2026-10-02T10:04:00+00:00"),
    ]

    result = detect_time_window(alerts)

    assert len(result) == 1
    assert result[0]["source_ip"] == "10.0.0.50"
    assert result[0]["username"] == "testuser"
    assert result[0]["failed_attempts"] == 5
    assert result[0]["severity"] == "HIGH"
