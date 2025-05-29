# OAuth2 Python

This sample code shows how to authenticate to Looker in order to run the
API using an OAuth2 flow, rather than using API credentials. The flow
is a PKCE style flow.

Gemini was used to generate most of this code. The important thing that
Gemini missed was the `include_client_id=True` parameter passed to
`oauth.fetch_token`. Without this parameter the token fetch failed with
an error "Failed Basic Authentication".

This code is presented as-is, with no warranties or support.

# Setup

## Prep

Setup a python virtual environment.

```
mkdir oauth-python
python -m venv oauth-python
cd oauth-python
source bin/activate
```

Copy `oauth.py` and `requirements.txt` there. Run
`pip install -r requirements.txt`

## Registering the OAuth Client App

To setup, you need to first register the OAuth Client App with Looker
using the API. This is easily done with API Explorer. Assuming API
Explorer is installed, go to the path
`/extensions/marketplace_extension_api_explorer::api-explorer/4.0/methods/Auth/register_oauth_client_app`
on your Looker instance. The `client_guid` is `oauth2python`. The body
should be set up like this:

```
{
  "redirect_uri": "http://localhost:8080/callback",
  "display_name": "OAuth2 Python",
  "description": "OAuth2 Python",
  "enabled": true,
  "group_id": ""
}
```

Run that. This only needs to be done once.

## Configuring the App

The configuration all takes place at the top of python program.

```
# --- Configuration ---
CLIENT_ID = 'oauth2python'
LOOKER_URL = 'https://sandbox.looker-devrel.com'
AUTHORIZATION_BASE_URL = f'{LOOKER_URL}/auth'
LOOKER_API_URL = 'https://sandbox.looker-devrel.com'
TOKEN_URL = f'{LOOKER_API_URL}/api/token'
REDIRECT_PORT = 8080 # Define port before using it in REDIRECT_URI
REDIRECT_URI = f'http://localhost:{REDIRECT_PORT}/callback' # Must be registered with your provider
SCOPES = ['cors_api'] # Your desired scopes
TOKEN_FILE = 'oauth_tokens.json'
```

`CLIENT_ID` should be set to the `client_guid` used in the API call
above.

`LOOKER_URL` should be set to the url of your Looker server. This is the path
to the Looker web server, which might have port `9999` as part of the url.

`LOOKER_API_URL` is set to the url of the Looker API server. It might have
port `19999` as part of the url.

`REDIRECT_PORT` is the port that will be opened in a local webserver. If
`REDIRECT_PORT` 8080 is in use, choose another number from 1024 to 65,535.
If this number is changed then the `redirect_uri` set up above will also
need to match.

`SCOPES` should not have to change.

`TOKEN_FILE` is the name of a file used to hold the token and refresh
token.

# Running

Run with the command `python oauth.py` You should get something like this:

```
Access token is expired.
Access token expired, refreshing...
Error refreshing token: 400 Client Error: Bad Request for url: https://sandbox.looker-devrel.com/api/token
Failed to refresh token. Will attempt full re-authorization.
Initiating new authorization flow...

Please go to this URL to authorize your application:
https://sandbox.looker-devrel.com/auth?response_type=code&client_id=oauth2python&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&scope=cors_api&state=...
Starting local server on http://localhost:8080/callback to catch redirect...
```

Now your browser should open and you will be acked to log on to
Looker and authorize the connection. Assuming you log on successfully
the process will continue...

```
127.0.0.1 - - [23/May/2025 13:23:07] "GET /callback?code=...
127.0.0.1 - - [23/May/2025 13:23:08] "GET /favicon.ico HTTP/1.1" 400 -

Received authorization code, exchanging for tokens...
Tokens saved to oauth_tokens.json
Tokens obtained and saved successfully.
API call successful!
{'display_name': 'Your Name',
 'email': 'xxxxxxxxx@google.com',
 'id': '1234'}
```

# Acknowledgements

Fabio Beltramini worked out the PKCE flow in his apps using TypeScript, and
walked me through the flow.
