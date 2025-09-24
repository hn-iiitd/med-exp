import os
import base64
import logging
import pandas as pd
import io
import re
import secrets
import json
import httplib2
from google_auth_httplib2 import AuthorizedHttp
import socket
import requests
from flask import jsonify
from flask import (
    Flask, request, jsonify, send_from_directory,
    redirect, url_for, session
)
from flask_cors import CORS
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

# ---------- Configuration ----------
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__, static_folder='static', static_url_path='/static')
CORS(app, supports_credentials=True)

SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/userinfo.email',
    'openid'
]
CLIENT_SECRETS_FILE = 'client_secrets.json'   # your client secrets
TOKEN_PATH = 'token.json'                     # saved token path

REDIRECT_URI = os.environ.get('REDIRECT_URI')  # e.g. "http://localhost:8081/auth/callback"
PORT = int(os.environ.get('PORT', 8081))

# Session secret
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

# ---------- Helpers ----------
def load_credentials():
    """Load credentials from TOKEN_PATH and refresh if necessary.
       Returns google.oauth2.credentials.Credentials or None if not available."""
    try:
        creds = None
        logger.debug(f"Checking for token file at: {TOKEN_PATH}")
        if os.path.exists(TOKEN_PATH):
            try:
                with open(TOKEN_PATH, 'r') as tf:
                    token_data = json.load(tf)
                # Check for required fields
                if 'refresh_token' not in token_data:
                    logger.error(f"Token file {TOKEN_PATH} missing refresh_token")
                    return None
                creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
                logger.debug("Loaded credentials from token file.")
            except ValueError as ve:
                logger.error(f"Invalid token file format: {ve}")
                return None
        else:
            logger.debug("No token file found.")

        if creds and creds.expired and creds.refresh_token:
            logger.debug("Credentials expired - refreshing...")
            try:
                creds.refresh(Request())
                with open(TOKEN_PATH, 'w') as tf:
                    tf.write(creds.to_json())
                logger.debug("Credentials refreshed and saved.")
            except Exception as re:
                logger.error(f"Failed to refresh credentials: {re}")
                return None
        if not creds or not creds.valid:
            logger.debug("No valid credentials available.")
            return None

        return creds
    except Exception as e:
        logger.exception(f"Error loading credentials: {e}")
        return None

def build_oauth_flow(redirect_uri=None):
    """Helper to build a Flow; prefer provided redirect_uri, then env REDIRECT_URI,
       then request.url_root + 'auth/callback' (caller must ensure request context exists)."""
    if redirect_uri:
        ri = redirect_uri
    elif REDIRECT_URI:
        ri = REDIRECT_URI
    else:
        ri = request.url_root.rstrip('/') + '/auth/callback'
    return Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=ri
    )

def walk_parts(parts):
    """Yield parts recursively (generator)."""
    for p in parts or []:
        yield p
        sub = p.get('parts')
        if sub:
            for q in walk_parts(sub):
                yield q

def extract_fields_from_df(df, sender_email):
    """Your extraction logic — unchanged except minor safety checks."""
    extracted = []
    for _, row in df.iterrows():
        med = batch = exp = mrp = distributor = None

        for col in df.columns:
            try:
                col_lower = str(col).lower()
                val = str(row[col])
            except Exception:
                continue

            if re.search(r'\b(item\s*name|particulars|item\s*description|description)\b', col_lower):
                med = val.strip()
            elif re.search(r'\b(batch\s*no|batchno|batch)\b', col_lower):
                batch = val.strip()
            elif re.search(r'\b(expiry|exp\s*dt|exp)\b', col_lower):
                exp = val.strip()
            elif re.search(r'\b(mrp|price|retail\s*price)\b', col_lower):
                try:
                    mrp = float(val.strip())
                except (ValueError, TypeError):
                    mrp = None
                    logger.debug(f"Could not parse MRP value: {val}")
            elif re.search(r'\b(distributor)\b', col_lower):
                distributor = val.strip()
                logger.debug(f"Found distributor in file: {distributor}")

        if med or batch or exp:
            distributor_value = distributor if distributor else (sender_email if sender_email else "Unknown")
            extracted.append({
                "medicine": med or "-",
                "batch_no": batch or "-",
                "expiry": exp or "-",
                "distributor": distributor_value,
                "mrp": mrp if mrp is not None else "-"
            })
    return extracted



def get_gmail_service(timeout: int = 30):
    """Return Gmail API service with per-request timeout, or None if auth required."""
    creds = load_credentials()
    if not creds:
        return None

    try:
        http = httplib2.Http(timeout=timeout)
        authed_http = AuthorizedHttp(creds, http=http)
        return build("gmail", "v1", http=authed_http, cache_discovery=False)
    except Exception as e:
        logger.exception("Failed to build Gmail service")
        return None


# ---------- OAuth endpoints ----------
@app.route('/auth/init')
def auth_init():
    """Redirects user to Google for auth (useful for manual testing in browser)."""
    flow = build_oauth_flow()
    auth_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'  # Changed to ensure refresh_token is issued
    )
    session['state'] = state
    logger.debug(f"Auth init: stored state and redirecting to Google. state={state}")
    return redirect(auth_url)

@app.route('/auth/callback')
def auth_callback():
    """OAuth callback that saves credentials to TOKEN_PATH."""
    logger.debug("Handling OAuth callback...")
    state = session.get('state')
    if not state:
        logger.error("No state in session during callback.")
        return jsonify({"error": "Session state missing"}), 400

    flow = build_oauth_flow()
    try:
        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials
        if not creds.refresh_token:
            logger.error("No refresh_token received in OAuth flow")
            return jsonify({"error": "Failed to obtain refresh_token from Google"}), 500
    except Exception as e:
        logger.exception(f"Error fetching token: {e}")
        return jsonify({"error": f"Failed to fetch token: {str(e)}"}), 500

    if not creds:
        logger.error("No credentials obtained from flow.")
        return jsonify({"error": "Failed to retrieve credentials"}), 500

    # Save token
    with open(TOKEN_PATH, 'w') as tf:
        tf.write(creds.to_json())
    logger.debug("Saved credentials to token file.")

    # Clean state
    session.pop('state', None)

    return redirect('/')

@app.route("/auth/google", methods=["POST"])
def google_login():
    """Optional client-side Google Sign-In verification route."""
    try:
        token = request.json.get("credential")
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request())
        email = idinfo.get("email")
        logger.debug(f"Authenticated email via id_token: {email}")
        return jsonify({"email": email})
    except Exception as e:
        logger.exception("Error in google_login")
        return jsonify({"error": str(e)}), 400

# ---------- Main API: fetch mails and extract attachments ----------
@app.route("/fetch-mails/<email>")
def fetch_mails(email):
    """
    Main endpoint:
      - If not authenticated -> returns JSON {auth_required: true, auth_url: "..."}
      - If authenticated -> fetch attachments, parse CSV/XLSX, extract fields, return JSON
    """
    try:
        service = get_gmail_service()
        if service is None:
            logger.debug("No Gmail credentials available -> returning auth_url to frontend.")
            flow = build_oauth_flow()
            auth_url, state = flow.authorization_url(
                access_type='offline',
                include_granted_scopes='true',
                prompt='consent'  # ensure refresh_token
            )
            session['state'] = state
            return jsonify({"auth_required": True, "auth_url": auth_url})

        # Verify authenticated user
        try:
            profile = service.users().getProfile(userId='me').execute()
            authenticated_email = profile.get('emailAddress')
        except (socket.timeout, requests.exceptions.RequestException, Exception) as e:
            logger.exception(f"Timeout/error fetching profile: {e}")
            return jsonify({"error": "Failed to fetch Gmail profile"}), 500

        if authenticated_email != email:
            logger.warning(f"Email mismatch: requested {email}, authenticated {authenticated_email}")
            return jsonify({"error": "Email does not match authenticated user"}), 403

        logger.debug("Listing messages with attachments...")
        try:
            results = service.users().messages().list(userId='me', q="has:attachment").execute()
            messages = results.get('messages', [])
        except (socket.timeout, requests.exceptions.RequestException, Exception) as e:
            logger.exception(f"Timeout/error listing messages: {e}")
            return jsonify({"error": "Failed to list Gmail messages"}), 500

        logger.debug(f"Found {len(messages)} messages with attachments.")
        extracted_data = []

        for msg in messages[:3000]:
            msg_id = msg.get('id')
            logger.debug(f"Processing message ID: {msg_id}")

            # Fetch message metadata
            try:
                msg_data = service.users().messages().get(
                    userId='me', id=msg_id, format='full'
                ).execute()
            except (socket.timeout, requests.exceptions.RequestException, Exception) as e:
                logger.exception(f"Timeout/error fetching message {msg_id}: {e}")
                continue  # Skip this message, don't kill the worker

            payload = msg_data.get('payload', {})
            headers = payload.get('headers', [])
            raw_from = next((h['value'] for h in headers if h.get('name','').lower() == 'from'), 'Unknown')
            email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', raw_from)
            sender_email = email_match.group(0) if email_match else 'Unknown'

            parts = payload.get('parts', [])
            for part in walk_parts(parts):
                filename = part.get('filename') or ''
                body = part.get('body', {}) or {}
                attachment_id = body.get('attachmentId') or body.get('body', {}).get('attachmentId')

                if not filename or not attachment_id:
                    continue

                filename_lower = filename.lower()
                if filename_lower.endswith(('.csv', '.xlsx', '.xls')):
                    logger.debug(f"Found attachment '{filename}' in message {msg_id}; downloading...")
                    try:
                        attachment = service.users().messages().attachments().get(
                            userId='me', messageId=msg_id, id=attachment_id
                        ).execute()

                        data = attachment.get('data') or attachment.get('body', {}).get('data')
                        if not data:
                            logger.warning(f"No data found for attachment {filename} in message {msg_id}")
                            continue

                        file_bytes = base64.urlsafe_b64decode(data.encode('utf-8'))

                        try:
                            if filename_lower.endswith('.csv'):
                                df = pd.read_csv(io.BytesIO(file_bytes))
                            else:
                                df = pd.read_excel(io.BytesIO(file_bytes))
                            logger.debug(f"Read file into DataFrame (rows={len(df)})")

                            extracted = extract_fields_from_df(df, sender_email)
                            extracted_data.extend(extracted)
                            logger.debug(f"Extracted {len(extracted)} rows from {filename}")
                        except Exception as e:
                            logger.exception(f"Failed to parse attachment {filename}: {e}")
                            continue

                    except (socket.timeout, requests.exceptions.RequestException, Exception) as e:
                        logger.exception(f"Timeout/error downloading attachment {filename} from message {msg_id}: {e}")
                        continue

        logger.debug(f"Returning {len(extracted_data)} extracted items.")
        return jsonify(extracted_data)

    except Exception as e:
        logger.exception("Error in fetch_mails")
        return jsonify({"error": str(e)}), 500

# ---------- Serve index (optional) ----------
@app.route('/')
def serve_index():
    try:
        return send_from_directory('.', 'index.html')
    except Exception:
        return jsonify({"status": "Server running"})

# ---------- Run ----------
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=PORT, debug=True)


