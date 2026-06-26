import re

def analyze_headers(email_text):

    results = {
        "spf": "Not Found",
        "dkim": "Not Found",
        "dmarc": "Not Found",
        "return_path": "Not Found",
        "risk": 0
    }

    spf = re.search(
        r"spf=(pass|fail|softfail|neutral)",
        email_text,
        re.IGNORECASE
    )

    dkim = re.search(
        r"dkim=(pass|fail)",
        email_text,
        re.IGNORECASE
    )

    dmarc = re.search(
        r"dmarc=(pass|fail)",
        email_text,
        re.IGNORECASE
    )

    return_path = re.search(
        r"Return-Path:\s*(.*)",
        email_text,
        re.IGNORECASE
    )

    if spf:
        results["spf"] = spf.group(1)

        if spf.group(1).lower() != "pass":
            results["risk"] += 15

    if dkim:
        results["dkim"] = dkim.group(1)

        if dkim.group(1).lower() != "pass":
            results["risk"] += 15

    if dmarc:
        results["dmarc"] = dmarc.group(1)

        if dmarc.group(1).lower() != "pass":
            results["risk"] += 15

    if return_path:
        results["return_path"] = return_path.group(1)

    return results