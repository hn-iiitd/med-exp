import os
import base64
import logging
import pandas as pd
import io
import socket
import re
import json

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='static', static_url_path='/static')
CORS(app)

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CLIENT_SECRETS_FILE = 'client_secrets.json'
TOKEN_PATH = 'token.json'

# Use environment variable for redirect URI
REDIRECT_URI = os.environ.get('REDIRECT_URI', 'http://localhost:8081/')

# Get port from environment variable or default to 8081 for local dev
PORT = int(os.environ.get('PORT', 8081))

def is_port_available(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('localhost', port))
            return True
        except socket.error:
            return False

def load_credentials():
    try:
        creds = None
        logger.debug(f"Checking for token file at: {TOKEN_PATH}")
        if os.path.exists(TOKEN_PATH):
            logger.debug("Token file found, loading credentials...")
            creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
        else:
            logger.debug("No token file found.")

        if not creds or not creds.valid:
            logger.debug("Credentials invalid or expired, refreshing or creating new...")
            if creds and creds.expired and creds.refresh_token:
                logger.debug("Refreshing credentials...")
                creds.refresh(Request())
            else:
                logger.debug(f"Starting OAuth flow with client secrets: {CLIENT_SECRETS_FILE}")
                
                # Load client secrets from environment variable
                client_secrets_data = os.environ.get('GOOGLE_CLIENT_SECRETS')
                if not client_secrets_data:
                    raise FileNotFoundError("GOOGLE_CLIENT_SECRETS environment variable not set")
                
                # Write client secrets to a temporary file
                with open(CLIENT_SECRETS_FILE, 'w') as f:
                    f.write(client_secrets_data)
                
                if not is_port_available(PORT) and 'localhost' in REDIRECT_URI:
                    raise RuntimeError(f"Port {PORT} is in use. Please free the port or use a different one.")
                
                flow = InstalledAppFlow.from_client_secrets_file(
                    CLIENT_SECRETS_FILE,
                    scopes=SCOPES,
                    redirect_uri=REDIRECT_URI
                )
                logger.debug("Running OAuth flow in local server mode...")
                try:
                    creds = flow.run_local_server(port=PORT, open_browser=False)
                except AttributeError:
                    logger.debug("run_local_server not available, falling back to run_console...")
                    creds = flow.run_console()
                logger.debug("OAuth flow completed.")
                
                # Save credentials to token file
                logger.debug("Saving new credentials to token file...")
                with open(TOKEN_PATH, 'w') as token_file:
                    token_file.write(creds.to_json())
        else:
            logger.debug("Credentials are valid.")
        return creds
    except Exception as e:
        logger.error(f"Error loading credentials: {str(e)}")
        raise

@app.route("/auth/google", methods=["POST"])
def google_login():
    try:
        token = request.json["credential"]
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request())
        email = idinfo["email"]
        logger.debug(f"Authenticated email: {email}")
        return jsonify({"email": email})
    except Exception as e:
        logger.error(f"Error in google_login: {str(e)}")
        return jsonify({"error": str(e)}), 400

def extract_fields_from_df(df, sender_email):
    extracted = []
    for _, row in df.iterrows():
        med = None
        batch = None
        exp = None
        mrp = None
        distributor = None

        for col in df.columns:
            col_lower = col.lower()
            val = str(row[col])

            if re.search(r'\b(item\s*name|particulars|item\s*description|description)\b', col_lower, re.IGNORECASE):
                med = val.strip()
            elif re.search(r'\b(batch\s*no|batchno|batch)\b', col_lower, re.IGNORECASE):
                batch = val.strip()
            elif re.search(r'\b(expiry|exp\s*dt|exp)\b', col_lower, re.IGNORECASE):
                exp = val.strip()
            elif re.search(r'\b(mrp|price|retail\s*price)\b', col_lower, re.IGNORECASE):
                try:
                    mrp = float(val.strip())
                except (ValueError, TypeError):
                    mrp = None
                    logger.debug(f"Could not parse MRP value: {val}")
            elif re.search(r'\b(distributor)\b', col_lower, re.IGNORECASE):
                distributor = val.strip()
                logger.debug(f"Found distributor in file: {distributor}")

        if med or batch or exp:
            distributor_value = distributor if distributor else sender_email if sender_email else "Unknown"
            extracted.append({
                "medicine": med or "-",
                "batch_no": batch or "-",
                "expiry": exp or "-",
                "distributor": distributor_value,
                "mrp": mrp if mrp is not None else "-"
            })
    return extracted

def get_gmail_service():
    try:
        creds = load_credentials()
        if not creds:
            raise Exception("Failed to load credentials")
        logger.debug("Building Gmail API service...")
        service = build("gmail", "v1", credentials=creds)
        return service
    except Exception as e:
        logger.error(f"Error in get_gmail_service: {str(e)}")
        raise

@app.route("/fetch-mails/<email>")
def fetch_mails(email):
    try:
        logger.debug(f"Fetching emails for: {email}")
        service = get_gmail_service()
        
        profile = service.users().getProfile(userId='me').execute()
        authenticated_email = profile.get('emailAddress')
        logger.debug(f"Authenticated user email: {authenticated_email}")
        if authenticated_email != email:
            logger.warning(f"Email mismatch: requested {email}, authenticated {authenticated_email}")
            return jsonify({"error": "Email does not match authenticated user"}), 403

        logger.debug("Listing messages with attachments...")
        results = service.users().messages().list(userId='me', q="has:attachment").execute()
        messages = results.get('messages', [])
        logger.debug(f"Found {len(messages)} messages with attachments.")

        extracted_data = []

        for msg in messages[:100]:
            logger.debug(f"Processing message ID: {msg['id']}")
            msg_data = service.users().messages().get(userId='me', id=msg['id']).execute()
            headers = msg_data['payload']['headers']
            sender_email = next((header['value'] for header in headers if header['name'].lower() == 'from'), 'Unknown')
            logger.debug(f"Raw From header: {sender_email}")
            
            email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', sender_email)
            sender_email = email_match.group(0) if email_match else 'Unknown'
            logger.debug(f"Extracted sender email: {sender_email}")

            parts = msg_data['payload'].get('parts', [])

            for part in parts:
                filename = part.get('filename')
                body = part.get('body', {})
                attachment_id = body.get('attachmentId')

                if attachment_id and (filename.endswith('.csv') or filename.endswith('.xlsx') or filename.endswith('.xls')):
                    logger.debug(f"Processing attachment: {filename}")
                    attachment = service.users().messages().attachments().get(
                        userId='me', messageId=msg['id'], id=attachment_id
                    ).execute()

                    file_data = base64.urlsafe_b64decode(attachment['data'])
                    try:
                        if filename.endswith('.csv'):
                            logger.debug(f"Reading CSV file: {filename}")
                            df = pd.read_csv(io.BytesIO(file_data))
                        elif filename.endswith('.xlsx') or filename.endswith('.xls'):
                            logger.debug(f"Reading Excel file: {filename}")
                            df = pd.read_excel(io.BytesIO(file_data))

                        extracted_data.extend(extract_fields_from_df(df, sender_email))
                        logger.debug(f"Extracted data from {filename}")

                    except Exception as e:
                        logger.error(f"Error reading {filename}: {str(e)}")

        logger.debug(f"Returning {len(extracted_data)} extracted items.")
        return jsonify(extracted_data)

    except Exception as e:
        logger.error(f"Error in fetch_mails: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=PORT, debug=True)