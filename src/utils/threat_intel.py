import os
import ipaddress

import requests
from dotenv import load_dotenv


load_dotenv()


ABUSEIPDB_URL = (
    "https://api.abuseipdb.com/api/v2/check"
)


def check_ip_reputation(
    ip_address: str,
    max_age_days: int = 90,
) -> dict:
    """
    Check an IP address against AbuseIPDB
    and return useful reputation information.
    """

    try:
        ipaddress.ip_address(ip_address)

    except ValueError:
        return {
            "success": False,
            "error": "Invalid IP address.",
        }

    api_key = os.getenv(
        "ABUSEIPDB_API_KEY"
    )

    if not api_key:
        return {
            "success": False,
            "error": (
                "AbuseIPDB API key is not configured."
            ),
        }

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers={
                "Accept": "application/json",
                "Key": api_key,
            },
            params={
                "ipAddress": ip_address,
                "maxAgeInDays": max_age_days,
            },
            timeout=10,
        )

    except requests.RequestException as e:
        return {
            "success": False,
            "error": (
                f"Threat intelligence request failed: {e}"
            ),
        }

    if response.status_code != 200:
        try:
            error_data = response.json()

        except ValueError:
            error_data = {}

        error_message = (
            "AbuseIPDB request failed."
        )

        if error_data.get("errors"):

            error_message = error_data[
                "errors"
            ][0].get(
                "detail",
                error_message,
            )

        return {
            "success": False,
            "error": (
                f"{error_message} "
                f"(HTTP {response.status_code})"
            ),
        }

    try:
        payload = response.json()

    except ValueError:
        return {
            "success": False,
            "error": (
                "AbuseIPDB returned an invalid response."
            ),
        }

    data = payload.get(
        "data",
        {},
    )

    return {
        "success": True,
        "ip_address": data.get(
            "ipAddress",
            ip_address,
        ),
        "is_public": data.get(
            "isPublic",
        ),
        "is_whitelisted": data.get(
            "isWhitelisted",
        ),
        "abuse_confidence_score": data.get(
            "abuseConfidenceScore",
        ),
        "country_code": data.get(
            "countryCode",
        ),
        "usage_type": data.get(
            "usageType",
        ),
        "isp": data.get(
            "isp",
        ),
        "domain": data.get(
            "domain",
        ),
        "total_reports": data.get(
            "totalReports",
        ),
        "last_reported_at": data.get(
            "lastReportedAt",
        ),
    }