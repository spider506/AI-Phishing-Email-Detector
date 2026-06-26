from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak
)

from reportlab.lib.styles import getSampleStyleSheet

def generate_pdf(result):

    pdf_file = "Phishing_Report.pdf"

    doc = SimpleDocTemplate(pdf_file)

    styles = getSampleStyleSheet()

    content = []

    content.append(
        Paragraph(
            "AI Phishing Detection SOC Incident Report",
            styles["Title"]
        )
    )

    content.append(Spacer(1, 20))

    content.append(
        Paragraph(
            "<b>Executive Summary</b>",
            styles["Heading2"]
        )
    )

    content.append(
        Paragraph(
            f"Verdict: {result['prediction']}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"Confidence: {result['confidence']}%",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"Risk Score: {result['risk_score']}/100",
            styles["BodyText"]
        )
    )

    if result["risk_score"] >= 75:
        severity = "CRITICAL"
    elif result["risk_score"] >= 50:
        severity = "HIGH"
    elif result["risk_score"] >= 25:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    content.append(
        Paragraph(
            f"Severity: {severity}",
            styles["BodyText"]
        )
    )

    content.append(Spacer(1, 15))

    content.append(
        Paragraph(
            "<b>Threat Indicators</b>",
            styles["Heading2"]
        )
    )

    if result["keywords"]:

        for keyword in result["keywords"]:

            content.append(
                Paragraph(
                    f"• {keyword}",
                    styles["BodyText"]
                )
            )

    else:

        content.append(
            Paragraph(
                "No suspicious keywords detected.",
                styles["BodyText"]
            )
        )

    content.append(Spacer(1, 15))

    content.append(
        Paragraph(
            "<b>URLs Detected</b>",
            styles["Heading2"]
        )
    )

    if result["urls"]:

        for url in result["urls"]:

            content.append(
                Paragraph(
                    url,
                    styles["BodyText"]
                )
            )

    else:

        content.append(
            Paragraph(
                "No URLs detected.",
                styles["BodyText"]
            )
        )

    content.append(Spacer(1, 15))

    content.append(
        Paragraph(
            "<b>Domain Intelligence</b>",
            styles["Heading2"]
        )
    )

    if result["domain_info"] and "error" not in result["domain_info"]:

        content.append(
            Paragraph(
                f"Domain: {result['domain_info']['domain']}",
                styles["BodyText"]
            )
        )

        content.append(
            Paragraph(
                f"Age: {result['domain_info']['age_days']} days",
                styles["BodyText"]
            )
        )

    else:

        content.append(
            Paragraph(
                "Domain intelligence unavailable.",
                styles["BodyText"]
            )
        )

    content.append(Spacer(1, 15))

    content.append(
        Paragraph(
            "<b>VirusTotal Analysis</b>",
            styles["Heading2"]
        )
    )

    if result["vt_result"] and "error" not in result["vt_result"]:

        content.append(
            Paragraph(
                f"Malicious: {result['vt_result']['malicious']}",
                styles["BodyText"]
            )
        )

        content.append(
            Paragraph(
                f"Suspicious: {result['vt_result']['suspicious']}",
                styles["BodyText"]
            )
        )

        content.append(
            Paragraph(
                f"Harmless: {result['vt_result']['harmless']}",
                styles["BodyText"]
            )
        )

        content.append(
            Paragraph(
                f"Undetected: {result['vt_result']['undetected']}",
                styles["BodyText"]
            )
        )

    else:

        content.append(
            Paragraph(
                "VirusTotal information unavailable.",
                styles["BodyText"]
            )
        )

    content.append(Spacer(1, 15))

    content.append(
        Paragraph(
            "<b>Email Header Analysis</b>",
            styles["Heading2"]
        )
    )

    if "header_info" in result:

        content.append(
            Paragraph(
                f"SPF: {result['header_info']['spf']}",
                styles["BodyText"]
            )
        )

        content.append(
            Paragraph(
                f"DKIM: {result['header_info']['dkim']}",
                styles["BodyText"]
            )
        )

        content.append(
            Paragraph(
                f"DMARC: {result['header_info']['dmarc']}",
                styles["BodyText"]
            )
        )

        content.append(
            Paragraph(
                f"Return Path: {result['header_info']['return_path']}",
                styles["BodyText"]
            )
        )

    content.append(Spacer(1, 15))

    content.append(
        Paragraph(
            "<b>Indicators of Compromise (IOC)</b>",
            styles["Heading2"]
        )
    )

    if "ioc_data" in result:

        for domain in result["ioc_data"]["domains"]:
            content.append(
                Paragraph(
                    f"Domain: {domain}",
                    styles["BodyText"]
                )
            )

        for email in result["ioc_data"]["emails"]:
            content.append(
                Paragraph(
                    f"Email: {email}",
                    styles["BodyText"]
                )
            )

        for ip in result["ioc_data"]["ips"]:
            content.append(
                Paragraph(
                    f"IP: {ip}",
                    styles["BodyText"]
                )
            )

    content.append(Spacer(1, 20))

    content.append(
        Paragraph(
            "<b>Analyst Conclusion</b>",
            styles["Heading2"]
        )
    )

    content.append(
        Paragraph(
            "This report was generated automatically by the AI Phishing Detection SOC Dashboard. Review all findings before making security decisions.",
            styles["BodyText"]
        )
    )

    doc.build(content)

    return pdf_file