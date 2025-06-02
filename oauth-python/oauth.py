#   Copyright 2025 Google, LLC
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

"""oauth"""

import os
import json
import urllib.parse
import threading
import time
import base64
import hashlib
import secrets
import pprint
from typing import Dict, Optional, Tuple, Any, List
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests
from requests_oauthlib import OAuth2Session

# --- Configuration ---
CLIENT_ID: str = "oauth2python"
LOOKER_URL: str = "https://sandbox.looker-devrel.com"
AUTHORIZATION_BASE_URL: str = f"{LOOKER_URL}/auth"
LOOKER_API_URL: str = "https://sandbox.looker-devrel.com"
TOKEN_URL: str = f"{LOOKER_API_URL}/api/token"
REDIRECT_PORT: int = 8080  # Define port before using it in REDIRECT_URI
REDIRECT_URI: str = (
  f"http://localhost:{REDIRECT_PORT}/callback"  # Must be registered with your provider
)
SCOPES: List[str] = ["cors_api"]  # Your desired scopes
TOKEN_FILE: str = "oauth_tokens.json"


# --- PKCE Generation ---
def generate_pkce_pair() -> Tuple[str, str]:
  """Generates a PKCE code_verifier and code_challenge."""
  # code_verifier: a high-entropy cryptographically random string from 43 to 128 octets long
  # (before base64url-encoding).
  # RFC 7636 suggests 32 octets for a good random source.
  code_verifier: str = secrets.token_urlsafe(
    96
  )  # Generates 128 characters safe for URL

  # code_challenge_method: S256 (SHA256 hash)
  # code_challenge: BASE64URL-encode(SHA256(ASCII(code_verifier)))
  s256: bytes = hashlib.sha256(code_verifier.encode("utf-8")).digest()
  code_challenge: str = base64.urlsafe_b64encode(s256).decode("utf-8").rstrip("=")

  return code_verifier, code_challenge


# --- Local HTTP Server for Redirect ---
class OAuthCallbackHandler(BaseHTTPRequestHandler):
  """OAuthCallbackHandler class"""

  server: "OAuthCallbackServer"  # Forward reference for type hint

  # pylint: disable-next=invalid-name
  def do_GET(self) -> None:
    """do_GET called on GET"""
    parsed_url: urllib.parse.ParseResult = urllib.parse.urlparse(self.path)
    query_params: Dict[str, List[str]] = urllib.parse.parse_qs(parsed_url.query)

    if "code" in query_params:
      auth_code: str = query_params["code"][0]
      self.server.auth_code = auth_code
      self.send_response(200)
      self.send_header("Content-type", "text/html")
      self.end_headers()
      self.wfile.write(b"Authorization successful! You can close this tab.")
    elif "error" in query_params:
      error: str = query_params["error"][0]
      error_description: str = query_params.get("error_description", [""])[0]
      self.server.auth_error = f"Error: {error}, Description: {error_description}"
      self.send_response(400)
      self.send_header("Content-type", "text/html")
      self.end_headers()
      self.wfile.write(
        f"Authorization failed: {error} - {error_description}".encode("utf-8")
      )
    else:
      self.send_response(400)
      self.send_header("Content-type", "text/html")
      self.end_headers()
      self.wfile.write(b"Authorization failed or code not found.")
    # Trigger server shutdown (non-blocking)
    threading.Thread(target=self.server.shutdown).start()


class OAuthCallbackServer(HTTPServer):
  """OAuthCallbackServer"""

  auth_code: Optional[str]
  auth_error: Optional[str]

  def __init__(self, server_address: Tuple[str, int], RequestHandlerClass: Type[BaseHTTPRequestHandler]):
    super().__init__(server_address, RequestHandlerClass)
    self.auth_code = None
    self.auth_error = None


def start_local_server_and_wait_for_code() -> OAuthCallbackServer:
  """start_local_server_and_wait_for_code"""

  host: Optional[str] = urllib.parse.urlparse(REDIRECT_URI).hostname
  # Ensure host is not None, though practically it should always be there for http/https URLs
  if host is None:
    raise ValueError("Could not parse hostname from REDIRECT_URI")
  port: int = REDIRECT_PORT
  server_address: Tuple[str, int] = (host, port)
  httpd = OAuthCallbackServer(server_address, OAuthCallbackHandler)
  print(f"Starting local server on {REDIRECT_URI} to catch redirect...")
  server_thread: threading.Thread = threading.Thread(target=httpd.serve_forever)
  server_thread.start()
  # Give a small delay for the server to start
  time.sleep(1)
  return httpd


# --- Token Management ---
def load_tokens() -> Optional[Dict[str, Any]]:
  """load_tokens"""
  if os.path.exists(TOKEN_FILE):
    with open(TOKEN_FILE, "r", encoding='utf-8') as f:
      tokens: Dict[str, Any] = json.load(f)
      return tokens
  return None


def save_tokens(tokens: Dict[str, Any]) -> None:
  """save_tokens"""
  # Add expiry time for future checks if not present
  if "expires_in" in tokens and "expires_at" not in tokens:
    tokens["expires_at"] = time.time() + tokens["expires_in"]
  with open(TOKEN_FILE, "w", encoding='utf-8') as f:
    json.dump(tokens, f, indent=4)
  print(f"Tokens saved to {TOKEN_FILE}")

def refresh_access_token(
  # pylint: disable-next=unused-argument
  oauth: OAuth2Session, tokens: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
  """refresh_access_token"""

  print("Access token expired, refreshing...")
  try:
    data: Dict[str, str] = {
      "grant_type": "refresh_token",
      "refresh_token": str(
        tokens["refresh_token"]
      ),  # Ensure refresh_token is string
      "client_id": CLIENT_ID,
      # 'client_secret': CLIENT_SECRET # For public clients, this is usually NOT included
    }
    response: requests.Response = requests.post(TOKEN_URL, data=data, timeout=300)
    response.raise_for_status()  # Raise an exception for HTTP errors
    new_tokens: Dict[str, Any] = response.json()
    save_tokens(new_tokens)
    print("Token refreshed successfully.")
    return new_tokens
  except requests.exceptions.RequestException as e:
    print(f"Error refreshing token: {e}")
    # Consider revoking the refresh token if it's consistently failing
    return None


def get_authorized_session() -> Optional[OAuth2Session]:
  """get_authorized_session"""

  tokens: Optional[Dict[str, Any]] = load_tokens()
  oauth: OAuth2Session = OAuth2Session(
    CLIENT_ID, scope=SCOPES, redirect_uri=REDIRECT_URI
  )

  if tokens:
    oauth.token = tokens
    # Check if access token is expired
    # Ensure 'expires_at' is present and is a number for comparison
    expires_at = tokens.get("expires_at")
    if (
      isinstance(expires_at, (int, float)) and expires_at < time.time() - 300
      ):  # Give a 5 min buffer
      print("Access token is expired.")
      refreshed_tokens = refresh_access_token(oauth, tokens)
      if not refreshed_tokens:
        print("Failed to refresh token. Will attempt full re-authorization.")
        tokens = None  # Force full re-authorization
      else:
        tokens = refreshed_tokens
        oauth.token = tokens  # Update session with new tokens
    elif "access_token" in tokens:
      print("Using existing valid access token.")
      return oauth

  if not tokens:  # No tokens, or refresh failed, initiate full authorization
    print("Initiating new authorization flow...")
    code_verifier, code_challenge = generate_pkce_pair()
    # print(f"Generated code_verifier (keep secret): {code_verifier}")
    # For debugging, DO NOT LOG IN PRODUCTION

    # Create the authorization URL with PKCE parameters
    authorization_url: str
    # pylint: disable-next=unused-variable
    state: str
    authorization_url, state = oauth.authorization_url(
      AUTHORIZATION_BASE_URL,
      code_challenge=code_challenge,
      code_challenge_method="S256",
    )

    print("\nPlease go to this URL to authorize your application:")
    print(authorization_url)
    webbrowser.open(authorization_url)

    # Start local server to capture the code
    httpd: OAuthCallbackServer = start_local_server_and_wait_for_code()

    # Wait for the server to finish serving the request (i.e., get the code)
    # We need to wait for the server thread to shut down before continuing
    # This is handled by threading.Thread(target=self.server.shutdown).start() in the handler
    httpd.serve_forever()  # This will block until shutdown() is called
    httpd.server_close()  # Ensure the socket is closed

    auth_code: Optional[str] = httpd.auth_code
    auth_error: Optional[str] = httpd.auth_error

    if auth_error:
      print(f"Authorization failed: {auth_error}")
      return None

    if not auth_code:
      print(
          "Failed to receive authorization code."
      )  # Removed "within timeout" as serve_forever blocks.
      return None

    print("\nReceived authorization code, exchanging for tokens...")
    try:
      token_response: Dict[str, Any] = oauth.fetch_token(
        token_url=TOKEN_URL,
        code=auth_code,
        code_verifier=code_verifier,  # Crucial for PKCE
        client_id=CLIENT_ID,
        # Client ID is often included in token exchange for public clients
        # client_secret=CLIENT_SECRET # For public clients, this is usually NOT included
        include_client_id=True,  # Crucial for PKCE
      )
      save_tokens(token_response)
      print("Tokens obtained and saved successfully.")
      return oauth
    except requests.exceptions.RequestException as e:
      print(f"Error exchanging code for tokens: {e}")
      if hasattr(e, "response") and e.response is not None:
        print(f"Response content: {e.response.text}")
      return None
  return oauth  # Should return the session if tokens were valid from the start and not expired


# --- Main Program Logic ---
def main() -> None:
  """Orchestrates the OAuth 2.0 authorization flow and makes a sample API call."""
  session: Optional[OAuth2Session] = get_authorized_session()
  if session:
    # Example API call (replace with your actual API endpoint)
    # The token is available as session.token
    try:
      api_url: str = f"{LOOKER_API_URL}/api/4.0/user?fields=id,display_name,email"
      response: requests.Response = session.get(api_url)
      response.raise_for_status()  # Raise an exception for HTTP errors
      print("API call successful!")
      api_data: Any = response.json()
      pprint.pprint(api_data)
    except requests.exceptions.RequestException as e:
      print(f"API call failed: {e}")
  else:
    print("Could not authorize application.")


if __name__ == "__main__":
  main()
