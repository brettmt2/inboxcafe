import base64
import json
from typing import Optional

from fastapi import Cookie, Request
from google.auth.exceptions import RefreshError
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow

from src.app.constants import SCOPES

def decode(data):
    return base64.urlsafe_b64decode(data).decode('utf-8')

def load_credentials(db, email: str) -> Credentials | None:
    cursor = db.cursor()
    cursor.execute(
        "SELECT credentials_json FROM user_credentials WHERE user_email = ?",
        (email,)
    )
    row = cursor.fetchone()

    if row is None:
        return None

    creds_json = row[0]
    return Credentials.from_authorized_user_info(
        info=json.loads(creds_json), scopes=SCOPES
    )

def get_email_from_session(db, session_id: str) -> str | None:
    '''
    get user's email using current session token if reauth is needed 
    '''
    cursor = db.cursor()
    cursor.execute(
        "SELECT user_email FROM sessions WHERE session_id = ?",
        (session_id,)
    )
    row = cursor.fetchone()

    if row is None:
        return None

    return row[0]

def build_flow():
    flow = Flow.from_client_secrets_file('credentials.json', scopes=SCOPES)
    flow.redirect_uri = 'http://localhost:8000/auth/callback'

    return flow

def save_credentials(db, email: str, creds: Credentials) -> None:
    if not creds.refresh_token:
        user_creds: Credentials = load_credentials(db=db, email=email)

        if not user_creds:
            return
        
        if user_creds.refresh_token:
            creds_dict = json.loads(creds.to_json())
            creds_dict['refresh_token'] = user_creds.refresh_token
            creds = Credentials.from_authorized_user_info(info=creds_dict, scopes=SCOPES)
        else:
            return

    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO user_credentials (user_email, credentials_json, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(user_email) DO UPDATE SET
            credentials_json = excluded.credentials_json,
            updated_at = CURRENT_TIMESTAMP
    """, (email, creds.to_json()))
    db.commit()

class RedirectException(Exception):
    pass

def validate_auth(request: Request, session_id: Optional[str] = Cookie(None)):
    if not session_id:
        print("no session_id cookie")
        raise RedirectException()

    db = request.app.state.db_conn

    email = get_email_from_session(db=db, session_id=session_id)
    if not email:
        print("session_id present but no matching email")
        raise RedirectException()

    creds = load_credentials(db=db, email=email)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            print("refreshing..")
            try:
                creds.refresh(GoogleRequest())
            except RefreshError:
                print("invalid refresh token... reauthenticate")
                raise RedirectException()
            
            save_credentials(db=db, email=email, creds=creds)
        else:
            print("no valid creds and refresh not possible")
            raise RedirectException()

    return creds