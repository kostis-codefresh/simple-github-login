package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var (
	oauthConfig *oauth2.Config
	// Key for encrypting session cookies (use a secure secret in production)
	store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))
)

// GitHub structures to parse API responses
type githubUser struct {
	Login string `json:"login"`
	Email string `json:"email"`
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func init() {
	// Fallback session key for development if environment variable is unset
	if os.Getenv("SESSION_KEY") == "" {
		store = sessions.NewCookieStore([]byte("super-secret-dev-key"))
	}

	baseURL := os.Getenv("APP_BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	oauthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		// Request access to read user profile and email addresses
		Scopes:      []string{"read:user", "user:email"},
		Endpoint:    github.Endpoint,
		RedirectURL: fmt.Sprintf("%s/callback", baseURL),
	}
}

func main() {
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/dashboard", handleDashboard)
	http.HandleFunc("/logout", handleLogout)
	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("web/assets"))))
	http.HandleFunc("/style.css", handleStyle)

	log.Println("Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// 1. Home Page: Login link
func handleHome(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "web/login.html")
}

func handleStyle(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "web/style.css")
}

// 2. Redirect user to GitHub OAuth
func handleLogin(w http.ResponseWriter, r *http.Request) {
	// "state" helps prevent CSRF attacks (use a random string in production)
	url := oauthConfig.AuthCodeURL("random-csrf-state")
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// 3. GitHub redirects back here
func handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	code := r.URL.Query().Get("code")

	// Exchange temporary code for access token (JSON response under the hood)
	token, err := oauthConfig.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Create an HTTP client that automatically adds "Authorization: Bearer <token>"
	client := oauthConfig.Client(ctx, token)

	// Fetch primary email address to check domain constraint
	email, err := getPrimaryEmail(client)
	if err != nil {
		http.Error(w, "Failed to fetch GitHub email: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// AUTHORIZATION CHECK: Must end in @octopus.com
	if !strings.HasSuffix(strings.ToLower(email), "@octopus.com") {
		http.Error(w, fmt.Sprintf("Access Denied: Your email (%s) is not a @octopus.com address.", email), http.StatusForbidden)
		return
	}

	// Fetch user profile to get the GitHub username
	username, err := getUsername(client)
	if err != nil {
		http.Error(w, "Failed to fetch GitHub username: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Store ONLY the username in a session cookie (Discard the GitHub token)
	session, _ := store.Get(r, "app-session")
	session.Values["username"] = username
	session.Save(r, w)

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// 4. Protected Dashboard
func handleDashboard(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "app-session")
	username, ok := session.Values["username"].(string)

	// Block unauthorized users
	if !ok || username == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	html := fmt.Sprintf(`
		<h1>Dashboard</h1>
		<p>Welcome, <strong>%s</strong>!</p>
		<a href="/logout">Logout</a>
	`, username)

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, html)
}

// 5. Logout
func handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "app-session")
	session.Values["username"] = ""
	session.Options.MaxAge = -1 // Deletes cookie
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --- Helper Functions to call GitHub API ---

func getPrimaryEmail(client *http.Client) (string, error) {
	resp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var emails []githubEmail
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", err
	}

	// Find the primary, verified email
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}

	// Fallback to first verified email if primary isn't marked explicitly
	for _, e := range emails {
		if e.Verified {
			return e.Email, nil
		}
	}

	return "", fmt.Errorf("no verified email found")
}

func getUsername(client *http.Client) (string, error) {
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var u githubUser
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return "", err
	}

	return u.Login, nil
}
