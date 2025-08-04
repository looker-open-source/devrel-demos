package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/pkg/browser"
	"golang.org/x/oauth2"
)

// --- Configuration ---
const (
	clientID             = "oauth2go"
	lookerURL            = "https://sandbox.looker-devrel.com"
	authorizationBaseURL = lookerURL + "/auth"
	tokenURL             = lookerURL + "/api/token"
	redirectPort         = "8080"
	redirectURL          = "http://localhost:" + redirectPort + "/callback"
	tokenFile            = "./oauth_tokens.json"
)

var (
	scopes = []string{"cors_api"}
)

// --- PKCE Generation ---
func generatePKCEPair() (string, string, error) {
	verifierBytes := make([]byte, 96)
	_, err := rand.Read(verifierBytes)
	if err != nil {
		return "", "", err
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	hasher := sha256.New()
	hasher.Write([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
	return verifier, challenge, nil
}

// --- Token Management ---
func loadTokens() (*oauth2.Token, error) {
	if _, err := os.Stat(tokenFile); os.IsNotExist(err) {
		return nil, nil
	}
	file, err := os.Open(tokenFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	tok := &oauth2.Token{}
	err = json.NewDecoder(file).Decode(tok)
	return tok, err
}

func saveTokens(token *oauth2.Token) error {
	file, err := os.OpenFile(tokenFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewEncoder(file).Encode(token)
}

// --- Local HTTP Server for Redirect ---
func startLocalServerAndWaitForCode(authURL string) (string, error) {
	codeChan := make(chan string)
	errChan := make(chan error)

	mux := http.NewServeMux()
	server := &http.Server{Addr: ":" + redirectPort, Handler: mux}

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			errMsg := "authorization failed: no code received"
			http.Error(w, errMsg, http.StatusBadRequest)
			errChan <- fmt.Errorf(errMsg)
			return
		}
		fmt.Fprintf(w, "Authorization successful! You can close this tab.")
		codeChan <- code
		go func() {
			time.Sleep(1 * time.Second)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := server.Shutdown(ctx); err != nil {
				log.Printf("HTTP server Shutdown error: %v", err)
			}
		}()
	})

	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	if err := browser.OpenURL(authURL); err != nil {
		log.Printf("Failed to open browser automatically. Please open this URL in your browser to continue: %s", authURL)
	}

	select {
	case code := <-codeChan:
		return code, nil
	case err := <-errChan:
		return "", err
	case <-time.After(5 * time.Minute):
		return "", fmt.Errorf("timed out waiting for authorization code")
	}
}

func generateSecureRandomString(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// --- Main Program Logic ---
func main() {
	conf := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: "", // Public client, no secret
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authorizationBaseURL,
			TokenURL: tokenURL,
		},
		RedirectURL: redirectURL,
	}

	token, err := loadTokens()
	if err != nil {
		log.Fatalf("Failed to load tokens: %v", err)
	}

	if token == nil || !token.Valid() {
		if token != nil {
			log.Println("Access token is expired, refreshing...")
			tokenSource := conf.TokenSource(context.Background(), token)
			newToken, err := tokenSource.Token()
			if err != nil {
				log.Printf("Failed to refresh token, initiating new authorization flow: %v", err)
				token = nil
			} else {
				token = newToken
				if err := saveTokens(token); err != nil {
					log.Fatalf("Failed to save new tokens: %v", err)
				}
				log.Println("Token refreshed and saved successfully.")
			}
		}

		if token == nil {
			log.Println("Initiating new authorization flow...")

			verifier, challenge, err := generatePKCEPair()
			if err != nil {
				log.Fatalf("Failed to generate PKCE pair: %v", err)
			}

			state, err := generateSecureRandomString(32)
			authURL := conf.AuthCodeURL(state, oauth2.AccessTypeOffline,
				oauth2.SetAuthURLParam("code_challenge", challenge),
				oauth2.SetAuthURLParam("code_challenge_method", "S256"))

			authCode, err := startLocalServerAndWaitForCode(authURL)
			if err != nil {
				log.Fatalf("Authorization failed: %v", err)
			}

			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{})
			token, err = conf.Exchange(ctx, authCode,
				oauth2.SetAuthURLParam("code_verifier", verifier))
			if err != nil {
				log.Fatalf("Failed to exchange token: %v", err)
			}

			if err := saveTokens(token); err != nil {
				log.Fatalf("Failed to save tokens: %v", err)
			}
			log.Println("Tokens obtained and saved successfully.")
		}
	} else {
		log.Println("Using existing valid access token.")
	}

	client := conf.Client(context.Background(), token)
	apiURL := fmt.Sprintf("%s/api/4.0/user?fields=id,display_name,email", lookerURL)
	resp, err := client.Get(apiURL)
	if err != nil {
		log.Fatalf("API call failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read API response: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		log.Fatalf("Failed to parse API response: %v", err)
	}

	fmt.Println("API call successful!")
	prettyJSON, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Fatalf("Failed to generate pretty JSON: %v", err)
	}
	fmt.Println(string(prettyJSON))
}
