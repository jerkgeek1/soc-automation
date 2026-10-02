def parse_alert(alert):
    """
    Extract important SOC investigation fields
    from a Wazuh Windows security alert.
    """

    return {
        "timestamp": alert.get("timestamp"),
        "agent_name": alert.get("agent", {}).get("name"),
        "agent_id": alert.get("agent", {}).get("id"),
        "rule_id": alert.get("rule", {}).get("id"),
        "rule_level": alert.get("rule", {}).get("level"),
        "rule_description": alert.get("rule", {}).get("description"),
        "event_id": alert.get("data", {}).get("win", {}).get("system", {}).get("eventID"),
        "username": alert.get("data", {}).get("win", {}).get("eventdata", {}).get("targetUserName"),
        "source_ip": alert.get("data", {}).get("win", {}).get("eventdata", {}).get("ipAddress") or "unknown",
        "logon_type": alert.get("data", {}).get("win", {}).get("eventdata", {}).get("logonType"),
    }
