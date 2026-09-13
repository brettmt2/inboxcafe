from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Cookie, Depends
from fastapi.responses import RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles


from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request as GoogleRequest

import sqlite3
from google.oauth2.credentials import Credentials

import json
import secrets
from typing import Optional

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
    cursor = db.cursor()
    cursor.execute(
        "SELECT user_email FROM sessions WHERE session_id = ?",
        (session_id,)
    )
    row = cursor.fetchone()

    if row is None:
        return None

    return row[0]

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

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.db_conn = sqlite3.connect("creds.db", check_same_thread=False)
    cursor = app.state.db_conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_credentials (
            user_email TEXT PRIMARY KEY,
            credentials_json TEXT NOT NULL,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            user_email TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    app.state.db_conn.commit()
    
    yield
    
    # shut down at app close
    app.state.db_conn.close()

app = FastAPI(lifespan=lifespan)

SCOPES = [
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/gmail.readonly",
    "openid"
]

flows = {}

def build_flow():
    flow = Flow.from_client_secrets_file('credentials.json', scopes=SCOPES)
    flow.redirect_uri = 'http://localhost:8000/auth/callback'

    return flow

class RedirectException(Exception):
    pass

@app.exception_handler(RedirectException)
def redirect_exception_handler(request: Request, exc: RedirectException):
    print("RedirectException caught, redirecting to /auth")
    return RedirectResponse(url="/auth")

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
            creds.refresh(GoogleRequest())
            save_credentials(db=db, email=email, creds=creds)
        else:
            print("no valid creds and refresh not possible")
            raise RedirectException()

    return creds

@app.get("/")
def home(creds=Depends(validate_auth)):
    return FileResponse("src/web/index.html")

@app.get("/auth")
def login(): # include request to avoid circular imports and use app context
    
    flow = build_flow()

    # first step of the OAuth flow - generate the authorization URL
    # using configuration of my client
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )

    flows[state] = flow

    return RedirectResponse(url=authorization_url)

@app.get("/auth/callback")
def callback(request: Request):
    db = request.app.state.db_conn

    # use the same flow for state persistence
    state = request.query_params.get("state")
    flow = flows.pop(state)

    url = str(request.url)
    flow.fetch_token(authorization_response=url)

    credentials = flow.credentials

    # get email address as id
    ps = build('people', 'v1', credentials=credentials)
    res = ps.people().get(resourceName='people/me', personFields="names,emailAddresses").execute()

    for addr in res.get("emailAddresses", []): # 0 is primary, according to google api docs. can update this
        if addr.get("metadata").get("primary") == True:
            email_address = addr.get("value")

    save_credentials(db, email_address, credentials)

    session_id = secrets.token_hex(32)
    response = RedirectResponse(url="/")
    response.set_cookie(
        key="session_id", 
        value=session_id,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=60 * 60 * 24 * 30  # 30 days
    )

    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO sessions (session_id, user_email) VALUES (?, ?)",
        (session_id, email_address)
    )
    db.commit()

    return response

@app.get("/api/user-info")
def get_user_info(creds=Depends(validate_auth)):
    ps = build('people', 'v1', credentials=creds)
    info_res = ps.people().get(resourceName='people/me', personFields="names,photos").execute()
    names = info_res.get('names', [])
    photos = info_res.get('photos', [])
    photo_url = 'default.jpg'
    name = "User"

    if names:
        name = names[0].get("displayName", name)
        print(name)

    if photos:
        photo_url = photos[0].get("url", photo_url)
        print(photo_url)

    return {"name": name, "photo_url": photo_url}

@app.get("/api/inbox")
def get_inbox(creds=Depends(validate_auth)):
    # returing top 5 for now
    gmail = build("gmail", "v1", credentials=creds)
    results = (gmail.users().messages().list(userId="me", labelIds=["INBOX"], q="category:primary", maxResults=5).execute())
    messages = results.get("messages", [])
    content = []

    if not messages:
        return {'content': "No messages found."}

    for message in messages:
        msg = (
            gmail.users().messages().get(userId="me", id=message["id"]).execute()
        )
        content.append(msg)

    return {'content': content}

app.mount("/static", StaticFiles(directory="src/web"), name="static")