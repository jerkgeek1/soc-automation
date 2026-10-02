def recommend_response(incident):
    """
    Generate a safe response recommendation
    based on incident severity and IP context.

    This module recommends actions only.
    It does not execute defensive actions.
    """

    severity = incident.get("severity", "LOW")
    ip_enrichment = incident.get("ip_enrichment", {})

    is_loopback = ip_enrichment.get("is_loopback", False)
    is_private = ip_enrichment.get("is_private", False)

    if is_loopback:
        return {
            "action": "INVESTIGATE_LOCAL_ACTIVITY",
            "automation": "NO_AUTO_BLOCK",
            "reason": (
                "Source IP is loopback. Investigate local authentication "
                "activity before taking defensive action."
            )
        }

    if severity == "HIGH" and not is_private:
        return {
            "action": "ESCALATE_AND_CONSIDER_CONTAINMENT",
            "automation": "MANUAL_APPROVAL_REQUIRED",
            "reason": (
                "High-severity activity from a non-private source. "
                "Escalate for analyst review and consider containment."
            )
        }

    if severity == "MEDIUM":
        return {
            "action": "INVESTIGATE_SOURCE",
            "automation": "NO_AUTO_BLOCK",
            "reason": (
                "Medium-severity authentication activity requires "
                "investigation and validation."
            )
        }

    return {
        "action": "MONITOR",
        "automation": "NO_AUTO_BLOCK",
        "reason": (
            "Insufficient evidence for automated containment. "
            "Continue monitoring."
        )
    }
