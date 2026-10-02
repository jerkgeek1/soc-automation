from collections import defaultdict


def correlate_failed_logins(alerts):
    """
    Group Windows failed-login events by
    source IP and username.
    """

    groups = defaultdict(list)

    for alert in alerts:
        if str(alert.get("event_id", "")) != "4625":
            continue

        source_ip = alert.get("source_ip", "unknown")
        username = alert.get("username", "unknown")

        key = (source_ip, username)
        groups[key].append(alert)

    results = []

    for (source_ip, username), events in groups.items():

        count = len(events)

        if count >= 5:
            severity = "HIGH"
        elif count >= 3:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        results.append({
            "source_ip": source_ip,
            "username": username,
            "failed_attempts": count,
            "severity": severity
        })

    return results
