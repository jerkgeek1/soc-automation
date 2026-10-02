def assess_severity(alert):
    """
    Assign an initial triage severity to a parsed SOC alert.

    These thresholds are lab rules for this project,
    not universal security standards.
    """

    event_id = str(alert.get("event_id", ""))
    rule_level = int(alert.get("rule_level", 0) or 0)

    # Windows failed logon
    if event_id == "4625":

        if rule_level >= 10:
            return "HIGH"

        elif rule_level >= 7:
            return "MEDIUM"

        else:
            return "LOW"

    # Unknown event type
    return "INFO"
