from flask import Flask, render_template, request, send_file
import joblib
import re
from urllib.parse import urlparse

from modules.url_checker import check_url
from modules.whois_checker import get_domain_info
from modules.keyword_analyzer import analyze_keywords
from modules.risk_engine import calculate_risk_score
from modules.db_manager import (
    init_db, save_scan, get_scans, get_dashboard_stats
)
from modules.pdf_report import generate_pdf
from modules.ioc_extractor import extract_iocs
from modules.header_analyzer import analyze_headers
from modules.gmail_fetcher import fetch_recent_emails

app = Flask(__name__)

init_db()

model = joblib.load(
"phishing_model.pkl"
)

latest_result = None

@app.route("/", methods=["GET", "POST"])
def home():
    global latest_result

    result_data = None

    if request.method == "POST":

        email_text = request.form["email"]

        prediction = model.predict(
            [email_text]
        )[0]

        probabilities = model.predict_proba(
            [email_text]
        )[0]

        confidence = round(
            max(probabilities) * 100,
            2
        )

        urls = re.findall(
            r'https?://\S+',
            email_text
        )

        keyword_info = analyze_keywords(
            email_text
        )

        ioc_data = extract_iocs(
            email_text
        )

        header_info = analyze_headers(
            email_text
        )

        vt_result = None
        domain_info = None

        malicious = 0
        suspicious = 0

        if urls:

            vt_result = check_url(
                urls[0]
            )

            if (
                vt_result and
                "malicious" in vt_result
            ):

                malicious = vt_result[
                    "malicious"
                ]

                suspicious = vt_result[
                    "suspicious"
                ]

            domain = urlparse(
                urls[0]
            ).netloc

            domain_info = get_domain_info(
                domain
            )

        domain_age = None

        if (
            domain_info and
            "age_days" in domain_info
        ):
            domain_age = domain_info[
                "age_days"
            ]

        risk_score = calculate_risk_score(
            prediction,
            malicious,
            suspicious,
            domain_age,
            keyword_info["score"],
            len(urls) > 0
        )

        risk_score += header_info["risk"]

        if risk_score > 100:
            risk_score = 100

        explanation = []

        if urls:
            explanation.append(
                "URL detected in email"
            )

        for keyword in keyword_info[
            "matches"
        ]:

            explanation.append(
                f"Keyword detected: {keyword}"
            )

        if malicious > 0:

            explanation.append(
                "VirusTotal flagged URL"
            )

        if (
            domain_age and
            domain_age < 180
        ):

            explanation.append(
                "Recently registered domain"
            )

        if (
            header_info["spf"] != "pass"
            and
            header_info["spf"] != "Not Found"
        ):
            explanation.append(
                "SPF validation failed"
            )

        if (
            header_info["dkim"] != "pass"
            and
            header_info["dkim"] != "Not Found"
        ):
            explanation.append(
                "DKIM validation failed"
            )

        if (
            header_info["dmarc"] != "pass"
            and
            header_info["dmarc"] != "Not Found"
        ):
            explanation.append(
                "DMARC validation failed"
            )

        verdict = (
            "⚠️ Phishing Email Detected"
            if prediction == 1
            else "✅ Legitimate Email"
        )

        result_data = {

            "prediction":
                verdict,

            "confidence":
                confidence,

            "risk_score":
                risk_score,

            "urls":
                urls,

            "keywords":
                keyword_info[
                    "matches"
                ],

            "vt_result":
                vt_result,

            "domain_info":
                domain_info,

            "explanation":
                explanation,

            "ioc_data":
                ioc_data,

            "header_info":
                header_info
        }

        latest_result = result_data

        save_scan(
            verdict,
            confidence,
            risk_score,
            ", ".join(urls)
        )

    stats = get_dashboard_stats()
    return render_template(
        "index.html",
        result=result_data,
        stats=stats
    )
@app.route("/history")
def history():
    scans = get_scans()

    return render_template(
        "history.html",
        scans=scans
    )

@app.route("/export")
def export_report():
    if not latest_result:
        return (
            "Analyze an email first "
            "before exporting."
        )

    pdf_file = generate_pdf(
        latest_result
    )

    return send_file(
        pdf_file,
        as_attachment=True
    )
@app.route("/gmail")
def gmail_scan():

    emails = fetch_recent_emails(10)

    results = []

    for email in emails:

        email_text = (
            email["subject"] +
            "\n\n" +
            email["body"]
        )

        prediction = model.predict(
            [email_text]
        )[0]

        probabilities = model.predict_proba(
            [email_text]
        )[0]
        print("\nEMAIL:", email["subject"])
        print("PROBABILITIES:", probabilities)

        confidence = round(
            max(probabilities) * 100,
            2
        )

        urls = re.findall(
            r'https?://\S+',
            email_text
        )

        keyword_info = analyze_keywords(
            email_text
        )

        ioc_data = extract_iocs(
            email_text
        )

        vt_result = None
        domain_info = None

        malicious = 0
        suspicious = 0

        if urls:

            vt_result = check_url(
                urls[0]
            )

            if (
                vt_result and
                "malicious" in vt_result
            ):

                malicious = vt_result[
                    "malicious"
                ]

                suspicious = vt_result[
                    "suspicious"
                ]

            domain = urlparse(
                urls[0]
            ).netloc

            domain_info = get_domain_info(
                domain
            )

        domain_age = None

        if (
            domain_info and
            "age_days" in domain_info
        ):
            domain_age = domain_info[
                "age_days"
            ]

        risk_score = calculate_risk_score(
            prediction,
            malicious,
            suspicious,
            domain_age,
            keyword_info["score"],
            len(urls) > 0
        )

        verdict = (
            "⚠️ Phishing"
            if prediction == 1
            else "✅ Legitimate"
        )

        results.append({

            "subject":
                email["subject"],

            "verdict":
                verdict,

            "confidence":
                confidence,

            "risk_score":
                risk_score,

            "urls":
                urls,

            "keywords":
                keyword_info["matches"],

            "ioc_data":
                ioc_data,

            "domain_info":
                domain_info,

            "vt_result":
                vt_result

        })

    return render_template(
        "gmail_results.html",
        results=results
    )


if __name__ == "__main__":
    app.run(debug=True)
