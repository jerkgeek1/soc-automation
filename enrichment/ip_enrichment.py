import ipaddress


def enrich_ip(ip):
    """
    Classify an IP address for SOC investigation.
    """

    if not ip:
        return {
            "ip": None,
            "type": "UNKNOWN",
            "is_private": False,
            "is_loopback": False,
        }

    try:
        address = ipaddress.ip_address(ip)

        if address.is_loopback:
            ip_type = "LOOPBACK"
        elif address.is_private:
            ip_type = "PRIVATE"
        elif address.is_global:
            ip_type = "PUBLIC"
        else:
            ip_type = "OTHER"

        return {
            "ip": ip,
            "type": ip_type,
            "is_private": address.is_private,
            "is_loopback": address.is_loopback,
        }

    except ValueError:
        return {
            "ip": ip,
            "type": "INVALID",
            "is_private": False,
            "is_loopback": False,
        }
