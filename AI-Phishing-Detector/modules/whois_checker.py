import whois
from datetime import datetime

def get_domain_info(domain):

    try:

        info = whois.whois(domain)

        creation_date = info.creation_date
        expiration_date = info.expiration_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        age_days = None

        if creation_date:

            if hasattr(creation_date, "tzinfo") and creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)

            age_days = (datetime.now() - creation_date).days

        return {
            "domain": domain,
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "age_days": age_days
        }

    except Exception as e:

        return {
            "error": str(e)
        }