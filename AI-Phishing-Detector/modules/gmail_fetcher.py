from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

import os
import pickle
import base64

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly"
]


def get_gmail_service():

    creds = None

    if os.path.exists("token.pickle"):

        with open("token.pickle", "rb") as token:

            creds = pickle.load(token)

    if not creds or not creds.valid:

        if creds and creds.expired and creds.refresh_token:

            creds.refresh(Request())

        else:

            flow = InstalledAppFlow.from_client_secrets_file(
                "credentials.json",
                SCOPES
            )

            creds = flow.run_local_server(
                port=0
            )

        with open("token.pickle", "wb") as token:

            pickle.dump(
                creds,
                token
            )

    service = build(
        "gmail",
        "v1",
        credentials=creds
    )

    return service


def fetch_recent_emails(limit=10):

    try:

        service = get_gmail_service()

        results = service.users().messages().list(
            userId="me",
            maxResults=limit
        ).execute()

        messages = results.get(
            "messages",
            []
        )

        emails = []

        for msg in messages:

            message = service.users().messages().get(
                userId="me",
                id=msg["id"]
            ).execute()

            payload = message.get(
                "payload",
                {}
            )

            headers = payload.get(
                "headers",
                []
            )

            subject = "No Subject"

            for header in headers:

                if header["name"] == "Subject":

                    subject = header["value"]

            body = ""

            if "parts" in payload:

                for part in payload["parts"]:

                    if part["mimeType"] == "text/plain":

                        data = part["body"].get(
                            "data"
                        )

                        if data:

                            body = base64.urlsafe_b64decode(
                                data
                            ).decode(
                                "utf-8",
                                errors="ignore"
                            )

            else:

                data = payload["body"].get(
                    "data"
                )

                if data:

                    body = base64.urlsafe_b64decode(
                        data
                    ).decode(
                        "utf-8",
                        errors="ignore"
                    )

            emails.append({

                "subject": subject,
                "body": body

            })

        return emails

    except Exception as e:

        print("GMAIL ERROR:", e)

        return []