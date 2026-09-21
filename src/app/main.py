import secrets
import sqlite3
from contextlib import asynccontextmanager
import json

from fastapi import Depends, FastAPI, Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from googleapiclient.discovery import build

from src.app.utils import RedirectException, build_flow, save_credentials, validate_auth, decode

flows = {}

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

@app.exception_handler(RedirectException)
def redirect_exception_handler(request: Request, exc: RedirectException):
    print("RedirectException caught, redirecting to /auth")
    return RedirectResponse(url="/auth")

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

    if photos:
        photo_url = photos[0].get("url", photo_url)

    return {"name": name, "photo_url": photo_url}

@app.get("/api/inbox")
def get_inbox(creds=Depends(validate_auth)):
    # TODO: pick last message in thread to display. nest rest of thread underneath
    gmail = build("gmail", "v1", credentials=creds)
    results = (gmail.users().threads().list(userId="me", labelIds=["INBOX"], q="category:primary").execute().get("threads", []))
    payloads = []

    for thread in results:
        tdata = (
            gmail.users().threads().get(userId="me", id=thread["id"]).execute()
        )

        msg = tdata["messages"][-1]["payload"]
        payloads.append(msg)

    return {"content": payloads}

app.mount("/static", StaticFiles(directory="src/web"), name="static")