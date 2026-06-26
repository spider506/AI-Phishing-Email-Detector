import re
from urllib.parse import urlparse

def extract_iocs(text):

    urls = re.findall(
        r'https?://[^\s]+',
        text
    )

    emails = re.findall(
        r'[\w\.-]+@[\w\.-]+\.\w+',
        text
    )

    ips = re.findall(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        text
    )

    domains = []

    for url in urls:

        try:
            domain = urlparse(url).netloc

            if domain not in domains:
                domains.append(domain)

        except:
            pass

    md5_hashes = re.findall(
        r'\b[a-fA-F0-9]{32}\b',
        text
    )

    sha1_hashes = re.findall(
        r'\b[a-fA-F0-9]{40}\b',
        text
    )

    sha256_hashes = re.findall(
        r'\b[a-fA-F0-9]{64}\b',
        text
    )

    return {
        "urls": urls,
        "domains": domains,
        "emails": emails,
        "ips": ips,
        "md5": md5_hashes,
        "sha1": sha1_hashes,
        "sha256": sha256_hashes
    }