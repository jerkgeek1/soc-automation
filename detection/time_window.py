from datetime import datetime
from collections import defaultdict


WINDOW_SECONDS = 300


def detect_time_window(alerts):
    """
    Correlate failed-login events occurring within
    a five-minute window for the same IP and username.

    Returns one result per IP + username group.
    """

    groups = defaultdict(list)

    for alert in alerts:

        if str(alert.get("event_id", "")) != "4625":
            continue

        timestamp = datetime.fromisoformat(
            alert["timestamp"].replace("Z", "+00:00")
        )

        source_ip = alert.get("source_ip", "unknown")
        username = alert.get("username", "unknown")

        key = (source_ip, username)

        groups[key].append(timestamp)

    results = []

    for (source_ip, username), timestamps in groups.items():

        timestamps.sort()

        max_count = 0
        best_window_start = None

        for i in range(len(timestamps)):

            window_start = timestamps[i]

            count = sum(
                1
                for timestamp in timestamps[i:]
                if (timestamp - window_start).total_seconds()
                <= WINDOW_SECONDS
            )

            if count > max_count:
                max_count = count
                best_window_start = window_start

        if max_count >= 5:
            severity = "HIGH"
        elif max_count >= 3:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        results.append({
            "source_ip": source_ip,
            "username": username,
            "window_start": best_window_start.isoformat(),
            "failed_attempts": max_count,
            "severity": severity
        })

    return results
