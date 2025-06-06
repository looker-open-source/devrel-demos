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

require 'webrick'
require 'net/http'
require 'json'
require 'uri'
require 'pkce_challenge'
require 'launchy'

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


# Use a simple in-memory hash to store the code_verifier between requests.
# In a real production app, you would use a more robust session store.
$session_store = {}

# Helper method for URL-safe Base64 encoding
def base64_url_encode(str)
  Base64.urlsafe_encode64(str, padding: false)
end

# Generate the PKCE code verifier and challenge
def generate_pkce_pair()
  pkce = PkceChallenge.challenge(char_length: 128)
  code_verifier = pkce.code_verifier
  code_challenge = pkce.code_challenge

  return code_verifier, code_challenge
end

def load_tokens()
  return nil unless File.exist?(TOKEN_FILE)
  s = File.stat(TOKEN_FILE)
  if !(s.mode.to_s(8)[3..5] == "600")
    say_error "#{TOKEN_FILE} mode is #{s.mode.to_s(8)[3..5]}. It must be 600. Ignoring."
    return nil
  end
  token_data = nil
  file = nil
  begin
    file = File.open(TOKEN_FILE)
    token_data = JSON.parse(file.read,{:symbolize_names => true})
  ensure
    file.close if file
  end
  token_data
end

def save_tokens(tokens)
  if tokens[:expires_in] and not tokens[:expires_at]
    tokens[:expires_at] = Time.now + tokens[:expires_in]
  end
  file = nil
  begin
    file = File.new(TOKEN_FILE, "wt")
    file.chmod(0600)
    file.write JSON.pretty_generate(tokens)
  ensure
    file.close if file
  end
end

def refresh_access_token(tokens)
  puts "Access token expired, refreshing..."
  begin
    data = {
      :grant_type => 'refresh_token',
      :refresh_token => tokens[:refresh_token],
      :client_id => CLIENT_ID
    }

    token_uri = URI(TOKEN_URL)

    http = Net::HTTP.new(token_uri.host, token_uri.port)
    http.use_ssl = true
    request = Net::HTTP::Post.new(token_uri.request_uri)
    request.set_form_data(data)

    token_response = http.request(request)
    new_tokens = JSON.parse(token_response.body,{:symbolize_names => true})
    if new_tokens[:error]
      puts "Error refreshing tokens"
      puts new_tokens
      return nil
    end
    save_tokens(new_tokens)
    puts "Token refreshed successfully"
    return new_tokens
  rescue Exception => e
    puts "Error refreshing token: #{e}"
    return nil
  end
end

def get_authorized_session()
  tokens = load_tokens()

  if tokens and tokens[:error]
    tokens = nil
  end

  if tokens
    if tokens[:expires_at]
      (day, time, tz) = tokens[:expires_at].split(' ')
      day_parts = day.split('-')
      time_parts = time.split(':')
      date_time_parts = day_parts + time_parts + [tz]
      expiration = Time.new(*date_time_parts)
      if expiration < (Time.now + 300)
        puts "Access token is expired"
        tokens = refresh_access_token(tokens)
      end
      if not tokens
        puts "Failed to refresh token. Will attempt full reauthorization"
        tokens = nil
      else
        # Update session with new tokens
        $session_store[:access_token] = tokens[:access_token]
      end
    elsif tokens[:access_token]
      puts "Using existing access token."
      $session_store[:access_token] = tokens[:access_token]
    end
  end

  if !tokens
    puts "Initializing new Authorization flow."
    # Create the authentication request
    code_verifier, code_challenge = generate_pkce_pair()
    $session_store[:code_verifier] = code_verifier
    $session_store[:state] = SecureRandom.urlsafe_base64(64)

    # Build the authorization URL
    auth_params = {
      response_type: 'code',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: SCOPE,
      state: $session_store[:state], # A random string for security
      code_challenge_method: 'S256',
      code_challenge: code_challenge
    }

    auth_uri = URI(AUTHORIZATION_BASE_URL)
    auth_uri.query = URI.encode_www_form(auth_params)

    puts "🚀 Starting server on http://localhost:#{REDIRECT_PORT}"
    server = configure_server(auth_uri)
    server.start

    if $session_store[:auth_error]
      puts "Authorization failed: #{$session_store[:auth_error]}"
      return nil
    end

    if not $session_store[:auth_code]
      puts "Failed to receive authorization code within timeout."
      return nil
    end

    puts "Received Authoriztion code, exchanging for tokens..."
    begin
      token_uri = URI(TOKEN_URL)

      token_request_body = {
        grant_type: 'authorization_code',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        code: $session_store[:auth_code],
        code_verifier: $session_store[:code_verifier] # Send the original verifier
      }

      # Make the POST request to the token endpoint
      http = Net::HTTP.new(token_uri.host, token_uri.port)
      http.use_ssl = true
      request = Net::HTTP::Post.new(token_uri.request_uri)
      request.set_form_data(token_request_body)

      token_response = http.request(request)
      token_data = JSON.parse(token_response.body,{:symbolize_names => true})

      save_tokens(token_data)

      if token_data[:error]
        puts "Error getting token:#{JSON.pretty_generate(token_data)}"
      end

      $session_store[:access_token] = token_data[:access_token]
    end
  end
end

def configure_server(auth_uri)
  # Create a new WEBrick server
  server = WEBrick::HTTPServer.new(
    Port: REDIRECT_PORT,
    StartCallback: -> {
      # direct the user's browser to the Looker login page
      Launchy.open(auth_uri.to_s)
    }
  )


  # Mount a handler for the callback URI ('/callback')
  # This is where Looker redirects after the user authenticates.
  server.mount_proc '/callback' do |req, res|
    # Extract the authorization code from the query parameters
    code = req.query['code']
    error = req.query['error']
    state = req.query['state']

    if code and state == $session_store[:state]
      $session_store[:auth_code] = code
      res.status = 200
      res.body = "Authorization successful! You can close this tab."
    elsif error
      error_description = req.query.get('error_description', '')
      $session_store[:auth_error] = "Error: #{error}, Description: #{error_description}"
      res.status = 400
      res.body = "Error: Authorization failed: #{error} - #{error_description}"
    else
      res.status = 400
      res.body = "Error: Authorization failed or code not found."
    end
    server.shutdown
  end

  return server
end

get_authorized_session()

access_token = $session_store[:access_token]

# Use the access token to make an authenticated API call
user_api_uri = URI("#{LOOKER_API_URL}/api/4.0/user?fields=id,display_name,email")

user_request = Net::HTTP::Get.new(user_api_uri.request_uri)
user_request['Authorization'] = "Bearer #{access_token}"

user_http = Net::HTTP.new(user_api_uri.host, user_api_uri.port)
user_http.use_ssl = true
user_response = user_http.request(user_request)
user_data = JSON.parse(user_response.body)

# Display the results
puts """
✅ Authentication Successful!
Your access token has been retrieved and used to call the API.

Access Token:
#{access_token[0..30]}...

API Response from /api/4.0/user:
#{JSON.pretty_generate(user_data)}
"""
