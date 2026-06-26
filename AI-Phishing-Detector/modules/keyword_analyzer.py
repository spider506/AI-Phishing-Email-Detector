PHISHING_KEYWORDS = [
    "urgent",
    "verify",
    "click here",
    "account suspended",
    "login immediately",
    "bank account",
    "password reset",
    "security alert",
    "confirm account",
    "limited time",
    "reset password",
    "update account",
    "payment failed"
]

def analyze_keywords(email_text):

    matches = []

    for keyword in PHISHING_KEYWORDS:

        if keyword.lower() in email_text.lower():
            matches.append(keyword)

    score = len(matches) * 10

    return {
        "matches": matches,
        "score": min(score, 40)
    }