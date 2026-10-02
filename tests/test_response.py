from response.recommendation import recommend_response


def test_loopback_response():

    incident = {
        "severity": "MEDIUM",
        "ip_enrichment": {
            "is_loopback": True,
            "is_private": True
        }
    }

    result = recommend_response(incident)

    assert result["action"] == "INVESTIGATE_LOCAL_ACTIVITY"
    assert result["automation"] == "NO_AUTO_BLOCK"


def test_high_severity_public_response():

    incident = {
        "severity": "HIGH",
        "ip_enrichment": {
            "is_loopback": False,
            "is_private": False
        }
    }

    result = recommend_response(incident)

    assert result["action"] == "ESCALATE_AND_CONSIDER_CONTAINMENT"
    assert result["automation"] == "MANUAL_APPROVAL_REQUIRED"


def test_medium_severity_response():

    incident = {
        "severity": "MEDIUM",
        "ip_enrichment": {
            "is_loopback": False,
            "is_private": True
        }
    }

    result = recommend_response(incident)

    assert result["action"] == "INVESTIGATE_SOURCE"
    assert result["automation"] == "NO_AUTO_BLOCK"


def test_low_severity_response():

    incident = {
        "severity": "LOW",
        "ip_enrichment": {
            "is_loopback": False,
            "is_private": True
        }
    }

    result = recommend_response(incident)

    assert result["action"] == "MONITOR"
    assert result["automation"] == "NO_AUTO_BLOCK"
