# oauth.rb

require 'webrick'
require 'net/http'
require 'json'
require 'uri'
require 'pkce_challenge'

# --- Configuration ---
# 1. Replace with the Client ID from your Looker OAuth Web Application client
CLIENT_ID = 'oauth2python'

# 2. Replace with your Looker instance URL (e.g., https://yourcompany.cloud.looker.com)
#    The API URL may have a different port like :19999
LOOKER_URL = 'https://sandbox.looker-devrel.com'
LOOKER_API_URL = 'https://sandbox.looker-devrel.com'

AUTHORIZATION_URL = "#{LOOKER_URL}/auth"
TOKEN_URL = "#{LOOKER_API_URL}/api/token"

# 3. The redirect URI must match what you configured in your GCP OAuth client
REDIRECT_PORT = 8080
REDIRECT_URI = "http://localhost:#{REDIRECT_PORT}/callback"

# 4. Define the API scope for the permissions you want to request
#    'cors_apu' allows us to use the api. It is the only scope curerently defined
SCOPE = 'cors_api'
# --- End Configuration ---


# Use a simple in-memory hash to store the code_verifier between requests.
# In a real production app, you would use a more robust session store.
$session_store = {}

# Helper method for URL-safe Base64 encoding
def base64_url_encode(str)
  Base64.urlsafe_encode64(str, padding: false)
end

# Create a new WEBrick server
server = WEBrick::HTTPServer.new(Port: REDIRECT_PORT)

# Mount a handler for the root path ('/')
# This page will start the authentication flow.
server.mount_proc '/' do |req, res|
  # Step 1: Generate the PKCE code verifier and challenge
  pkce = PkceChallenge.challenge(char_length: 128)
  $session_store[:code_verifier] = pkce.code_verifier

  code_challenge = pkce.code_challenge

  # Step 2: Build the authorization URL
  auth_params = {
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: SCOPE,
    state: '12345_just_a_demo_state', # A random string for security
    code_challenge_method: 'S256',
    code_challenge: code_challenge
  }

  auth_uri = URI(AUTHORIZATION_URL)
  auth_uri.query = URI.encode_www_form(auth_params)

  # Step 3: Redirect the user's browser to the Looker login page
  res.status = 302
  res['Location'] = auth_uri.to_s
  res.body = "Redirecting you to Looker to log in..."
end

# Mount a handler for the callback URI ('/callback')
# This is where Looker redirects after the user authenticates.
server.mount_proc '/callback' do |req, res|
  # Step 4: Extract the authorization code from the query parameters
  auth_code = req.query['code']

  if auth_code.nil?
    res.status = 400
    res.body = "Error: No authorization code received."
    next
  end

  # Step 5: Exchange the authorization code for an access token
  token_uri = URI(TOKEN_URL)

  token_request_body = {
    grant_type: 'authorization_code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    code: auth_code,
    code_verifier: $session_store[:code_verifier] # Send the original verifier
  }

  # Make the POST request to the token endpoint
  http = Net::HTTP.new(token_uri.host, token_uri.port)
  http.use_ssl = true
  request = Net::HTTP::Post.new(token_uri.request_uri)
  request.set_form_data(token_request_body)

  token_response = http.request(request)
  token_data = JSON.parse(token_response.body)

  if token_data['error']
    res.status = 401
    res.body = "<h3>Error getting token:</h3><pre>#{JSON.pretty_generate(token_data)}</pre>"
    next
  end

  access_token = token_data['access_token']

  # Step 6: Use the access token to make an authenticated API call
  user_api_uri = URI("#{LOOKER_API_URL}/api/4.0/user?fields=id,display_name,email")

  user_request = Net::HTTP::Get.new(user_api_uri.request_uri)
  user_request['Authorization'] = "Bearer #{access_token}"

  user_http = Net::HTTP.new(user_api_uri.host, user_api_uri.port)
  user_http.use_ssl = true
  user_response = user_http.request(user_request)
  user_data = JSON.parse(user_response.body)

  # Display the results
  res.status = 200
  res['Content-Type'] = 'text/html'
  res.body = """
  <h1>✅ Authentication Successful!</h1>
  <p>Your access token has been retrieved and used to call the API.</p>

  <h2>Access Token:</h2>
  <pre>#{access_token[0..30]}...</pre>

  <h2>API Response from /api/4.0/user:</h2>
  <pre>#{JSON.pretty_generate(user_data)}</pre>
  """
end

# Start the server and handle shutdown
trap('INT') { server.shutdown }

puts "🚀 Starting server on http://localhost:8080"
puts "Visit http://localhost:8080 in your browser to begin authentication."
server.start
