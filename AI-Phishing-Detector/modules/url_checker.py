import requests
import time

API_KEY = "85832b188b95b1c2dc8f2d9f46fb8cd24e1ee004b46e031cd0b22cd56aec036b"

def check_url(url):
    try:

        headers = {
            "x-apikey": API_KEY
        }

        submit_response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )

        if submit_response.status_code not in [200, 202]:
            return {
                "error": f"Submit Error: {submit_response.status_code}"
            }

        analysis_id = submit_response.json()["data"]["id"]

        for _ in range(5):
            time.sleep(10)

            analysis_response = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers
            )

            if analysis_response.status_code != 200:
                return {
                    "error": f"Analysis Error: {analysis_response.status_code}"
                }

            analysis_data = analysis_response.json()

            if analysis_data["data"]["attributes"]["status"] == "completed":
                break

        else:
            return {
                "error": "Analysis did not complete in time"
            }

        stats = analysis_data["data"]["attributes"]["stats"]

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0)
        }

    except Exception as e:
        return {
            "error": str(e)
        }