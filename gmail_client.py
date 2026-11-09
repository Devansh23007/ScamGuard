"""Thin wrapper around the Gmail API (OAuth + list/read/label)."""
from __future__ import annotations
import os

import config

READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
MODIFY_SCOPE = "https://www.googleapis.com/auth/gmail.modify"   # read + labels; cannot permanently delete


def scopes() -> list[str]:
    return [READONLY_SCOPE] if config.GMAIL_READONLY else [MODIFY_SCOPE]


def get_service(credentials_file: str = "credentials.json", token_file: str = "token.json"):
    # google libs imported lazily so the rest of the project works without them
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build

    creds = None
    if os.path.exists(token_file):
        creds = Credentials.from_authorized_user_file(token_file, scopes())
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception:
                creds = None   # revoked/expired (common in Google 'Testing' mode): re-authorize
        if not creds or not creds.valid:
            if not os.path.exists(credentials_file):
                raise FileNotFoundError(
                    f"{credentials_file} not found. Follow SETUP_GMAIL.md to download it from Google Cloud.")
            flow = InstalledAppFlow.from_client_secrets_file(credentials_file, scopes())
            creds = flow.run_local_server(port=0)
        with open(token_file, "w") as f:
            f.write(creds.to_json())
    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def list_message_ids(service, query: str, limit: int = 200) -> list[str]:
    ids, token = [], None
    while len(ids) < limit:
        resp = service.users().messages().list(
            userId="me", q=query, maxResults=min(100, limit - len(ids)), pageToken=token).execute()
        ids += [m["id"] for m in resp.get("messages", [])]
        token = resp.get("nextPageToken")
        if not token:
            break
    return ids


def get_message(service, msg_id: str) -> dict:
    return service.users().messages().get(userId="me", id=msg_id, format="full").execute()


def ensure_label(service, name: str) -> str:
    for lb in service.users().labels().list(userId="me").execute().get("labels", []):
        if lb["name"] == name:
            return lb["id"]
    body = {"name": name, "labelListVisibility": "labelShow", "messageListVisibility": "show"}
    return service.users().labels().create(userId="me", body=body).execute()["id"]


def add_label(service, msg_id: str, label_id: str) -> None:
    service.users().messages().modify(userId="me", id=msg_id, body={"addLabelIds": [label_id]}).execute()
