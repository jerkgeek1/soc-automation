def detect_failed_login_pattern(alerts):
    """
    Detect repeated Windows failed-login events.

    Lab thresholds:
    1-2 failures -> LOW
    3-4 failures -> MEDIUM
    5+ failures  -> HIGH
    """

    failed_logins = [
        alert for alert in alerts
        if str(alert.get("event_id", "")) == "4625"
    ]

    count = len(failed_logins)

    if count >= 5:
        severity = "HIGH"
    elif count >= 3:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "event_count": count,
        "severity": severity
    }
