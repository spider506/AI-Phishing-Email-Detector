def calculate_risk_score(
        ml_prediction,
        malicious_count,
        suspicious_count,
        domain_age,
        keyword_score,
        has_url):

    score = 0

    if ml_prediction == 1:
        score += 30

    score += keyword_score

    if has_url:
        score += 15

    score += malicious_count * 5
    score += suspicious_count * 3

    if domain_age is not None:

        if domain_age < 30:
            score += 25

        elif domain_age < 180:
            score += 15

    return min(score, 100)