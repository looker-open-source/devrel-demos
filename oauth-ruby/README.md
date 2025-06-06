# OAuth2 Ruby

This sample code shows how to authenticate to Looker in order to run the
API using an OAuth2 flow, rather than using API credentials. The flow
is a PKCE style flow.

Gemini was used to generate most of this code.

This code is presented as-is, with no warranties or support.

# Setup

## Prep


```
mkdir oauth-ruby
```

Copy `oauth.rb` and `Gemfile` there. Run
`bundle install`

## Registering the OAuth Client App

To setup, you need to first register the OAuth Client App with Looker
using the API. This is easily done with API Explorer. Assuming API
Explorer is installed, go to the path
`/extensions/marketplace_extension_api_explorer::api-explorer/4.0/methods/Auth/register_oauth_client_app`
on your Looker instance. The `client_guid` is `oauth2ruby`. The body
should be set up like this:

```
{
  "redirect_uri": "http://localhost:8080/callback",
  "display_name": "OAuth2 Ruby Sample App",
  "description": "OAuth2 Ruby Sample App",
  "enabled": true,
  "group_id": ""
}
```

Run that. This only needs to be done once.

## Configuring the App

The configuration all takes place at the top of the Ruby program.

```
# --- Configuration ---
CLIENT_ID = 'oauth2ruby'
LOOKER_URL = 'https://sandbox.looker-devrel.com'
AUTHORIZATION_BASE_URL = "#{LOOKER_URL}/auth"
LOOKER_API_URL = 'https://sandbox.looker-devrel.com'
TOKEN_URL = "#{LOOKER_API_URL}/api/token"
REDIRECT_PORT = 8080
REDIRECT_URI = "http://localhost:#{REDIRECT_PORT}/callback"
SCOPE = 'cors_api'
TOKEN_FILE = 'oauth_tokens.json'
# --- End Configuration ---
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

Run with the command `ruby oauth.rb` You should get something like this:

```
Initializing new Authorization flow.
🚀 Starting server on http://localhost:8080
[2025-06-06 12:20:50] INFO  WEBrick 1.9.1
[2025-06-06 12:20:50] INFO  ruby 3.1.3 (2022-11-24) [x86_64-linux]
[2025-06-06 12:20:50] INFO  WEBrick::HTTPServer#start: pid=3162073 port=8080
Opening in existing browser session.
```

Now your browser should open and you will be acked to log on to
Looker and authorize the connection. Assuming you log on successfully
the process will continue...

```
[2025-06-06 12:20:51] INFO  going to shutdown ...
[2025-06-06 12:20:51] INFO  WEBrick::HTTPServer#start done.
Received Authoriztion code, exchanging for tokens...

✅ Authentication Successful!
Your access token has been retrieved and used to call the API.

Access Token:
CHjrWVtrwnY7dHbVqF9mYpv6gPGY8xT...

API Response from /api/4.0/user:
{
 'display_name': 'Your Name',
 'email': 'xxxxxxxxx@google.com',
 'id': '1234'
}
```

# Acknowledgements

Fabio Beltramini worked out the PKCE flow in his apps using TypeScript, and
walked me through the flow.
