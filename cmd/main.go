package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/jmespath/go-jmespath"
	"golang.org/x/oauth2"
)

// Config holds all environment and flag parameters
type Config struct {
	RouterURL      *url.URL
	AdminLogin     string
	AdminPass      string
	ViewerLogin    string
	ViewerPass     string
	SessionAuthKey []byte
	SessionEncKey  []byte
	OIDCIssuer     string
	OAuth2ClientID string
	OAuth2Secret   string
	OAuth2Redirect string
	OAuth2Scopes   []string
	JMESRoleQuery  string
}

var (
	cfg          Config
	sessionStore *sessions.CookieStore
	oauth2Config *oauth2.Config
	oidcVerifier *oidc.IDTokenVerifier

	// global CookieJars per role
	adminJar  http.CookieJar
	viewerJar http.CookieJar
	jarMu     sync.Mutex
)

// contextKey is a type for context keys
type contextKey string

const (
	roleKey contextKey = "role"
)

func main() {
	// Load configuration from env or flags
	var rawRouter string
	flag.StringVar(&rawRouter, "router_url", os.Getenv("ROUTER_URL"), "Router base URL (with or without scheme)")
	flag.StringVar(&cfg.AdminLogin, "admin_user", os.Getenv("ADMIN_USER"), "Admin login for router (optional)")
	flag.StringVar(&cfg.AdminPass, "admin_pass", os.Getenv("ADMIN_PASS"), "Admin password for router (optional)")
	flag.StringVar(&cfg.ViewerLogin, "viewer_user", os.Getenv("VIEWER_USER"), "Viewer login for router (optional)")
	flag.StringVar(&cfg.ViewerPass, "viewer_pass", os.Getenv("VIEWER_PASS"), "Viewer password for router (optional)")
	var sessionSecret string
	flag.StringVar(&sessionSecret, "session_secret", os.Getenv("SESSION_SECRET"), "Session auth key (>=32 bytes)")
	flag.StringVar(&cfg.OIDCIssuer, "oidc_issuer", os.Getenv("OIDC_ISSUER"), "OIDC issuer URL")
	flag.StringVar(&cfg.OAuth2ClientID, "oauth2_client_id", os.Getenv("OAUTH2_CLIENT_ID"), "OAuth2 client ID")
	flag.StringVar(&cfg.OAuth2Secret, "oauth2_secret", os.Getenv("OAUTH2_SECRET"), "OAuth2 client secret")
	flag.StringVar(&cfg.OAuth2Redirect, "oauth2_redirect", os.Getenv("OAUTH2_REDIRECT"), "OAuth2 redirect URL")
	flag.StringVar(&cfg.JMESRoleQuery, "jmes_query", os.Getenv("JMES_ROLE_QUERY"), "JMESPath role expression")
	var scopesEnv string
	flag.StringVar(&scopesEnv, "oauth2_scopes", os.Getenv("OAUTH2_SCOPES"), "Comma-separated OAuth2 scopes")
	flag.Parse()

	// Normalize router URL schema
	if !strings.HasPrefix(rawRouter, "http://") && !strings.HasPrefix(rawRouter, "https://") {
		rawRouter = "http://" + rawRouter
	}
	ru, err := url.Parse(strings.TrimRight(rawRouter, "/"))
	if err != nil {
		log.Fatalf("invalid router_url: %v", err)
	}
	cfg.RouterURL = ru

	// Validate internal creds optionality
	// If only one role cred is provided, only that role is allowed

	// Validate session keys
	if len(sessionSecret) < 32 {
		log.Fatal("SESSION_SECRET must be at least 32 bytes for signing and encryption")
	}
	cfg.SessionAuthKey = []byte(sessionSecret)
	// derive encryption key
	e := sha256.Sum256([]byte(sessionSecret))
	cfg.SessionEncKey = e[:]

	// Init session store with auth and encryption keys
	sessionStore = sessions.NewCookieStore(cfg.SessionAuthKey, cfg.SessionEncKey)
	sessionStore.Options = &sessions.Options{
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		// default 1h session
		MaxAge: 3600,
		Path:   "/",
	}

	// OAuth2/OIDC setup
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, cfg.OIDCIssuer)
	if err != nil {
		log.Fatalf("failed to initialize OIDC provider: %v", err)
	}
	oauth2Config = &oauth2.Config{
		ClientID:     cfg.OAuth2ClientID,
		ClientSecret: cfg.OAuth2Secret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.OAuth2Redirect,
		Scopes:       append([]string{oidc.ScopeOpenID, "profile", "email"}, strings.Split(scopesEnv, ",")...),
	}
	oidcVerifier = provider.Verifier(&oidc.Config{ClientID: cfg.OAuth2ClientID})

	// Initialize global jars
	adminJar, _ = cookiejar.New(nil)
	viewerJar, _ = cookiejar.New(nil)

	// Setup reverse proxy
	revProxy := httputil.NewSingleHostReverseProxy(cfg.RouterURL)
	// Ensure Director strips client cookies and sets target
	origDirector := revProxy.Director
	revProxy.Director = func(req *http.Request) {
		origDirector(req)
		req.Header.Del("Cookie")
	}
	revProxy.Transport = &KeeneticTransport{Base: defaultTransport()}
	revProxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Del("Set-Cookie")
		return nil
	}

	// Setup router with middleware
	r := mux.NewRouter()
	r.Use(recoveryMiddleware)
	r.HandleFunc("/healthz", healthHandler)
	r.HandleFunc("/ready", readyHandler)
	r.HandleFunc("/oauth2/callback", callbackHandler)
	r.PathPrefix("/").Handler(oauthMiddleware(revProxy))

	// Start server
	srv := &http.Server{
		Addr:         ":8080",
		Handler:      r,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	go func() {
		log.Println("server starting on :8080")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("shutdown signal received")
	ctxShut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctxShut); err != nil {
		log.Fatalf("server shutdown failed: %v", err)
	}
	log.Println("server exited")
}

// defaultTransport returns a base transport with timeouts
func defaultTransport() http.RoundTripper {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	tr.TLSHandshakeTimeout = 5 * time.Second
	return tr
}

// recoveryMiddleware recovers from panics in handlers
func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic recovered: %v", rec)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func readyHandler(w http.ResponseWriter, r *http.Request) {
	healthHandler(w, r)
}

// oauthMiddleware enforces OAuth2 flow and stores role in context
func oauthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, _ := sessionStore.Get(r, "proxy-session")
		role, ok := sess.Values["role"].(string)
		if !ok || (role != "Admin" && role != "Viewer") {
			// initiate OAuth2 flow
			state := uuid.NewString()
			nonce := uuid.NewString()
			sess.Values["state"] = state
			sess.Values["nonce"] = nonce
			sess.Values["return_to"] = r.URL.RequestURI()
			sess.Save(r, w)
			http.Redirect(w, r, oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("nonce", nonce)), http.StatusFound)
			return
		}
		// pass role in context for transport
		r2 := r.WithContext(context.WithValue(r.Context(), roleKey, role))
		next.ServeHTTP(w, r2)
	})
}

// callbackHandler handles OAuth2 redirect, verifies state, nonce, and JMESPath role
func callbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.WithValue(r.Context(), oauth2.HTTPClient, &http.Client{Timeout: 5 * time.Second})
	sess, _ := sessionStore.Get(r, "proxy-session")
	// verify state
	if r.URL.Query().Get("state") != sess.Values["state"] {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	// exchange code
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "code missing", http.StatusBadRequest)
		return
	}
	tok, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return
	}
	// verify ID token
	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		http.Error(w, "missing id_token", http.StatusInternalServerError)
		return
	}
	idToken, err := oidcVerifier.Verify(ctx, rawID)
	if err != nil {
		http.Error(w, "id token invalid", http.StatusUnauthorized)
		return
	}
	// check nonce
	if idToken.Nonce != sess.Values["nonce"] {
		http.Error(w, "invalid nonce", http.StatusUnauthorized)
		return
	}
	// build claims from ID token instead of userinfo
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "failed to parse id_token claims", http.StatusInternalServerError)
		return
	}
	// evaluate role
	roleVal, err := jmespath.Search(cfg.JMESRoleQuery, claims)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "forbidden: role parsing error", http.StatusForbidden)
		return
	}
	role, ok := roleVal.(string)
	if !ok || (role != "Admin" && role != "Viewer") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// ensure credentials exist for role
	if (role == "Admin" && cfg.AdminLogin == "") || (role == "Viewer" && cfg.ViewerLogin == "") {
		http.Error(w, "no credentials configured for role", http.StatusForbidden)
		return
	}
	// store role
	sess.Values["role"] = role
	sess.Options.MaxAge = 3600
	sess.Save(r, w)

	// redirect back
	ret := "/"
	if to, ok := sess.Values["return_to"].(string); ok {
		ret = to
	}
	http.Redirect(w, r, ret, http.StatusFound)
}

// KeeneticTransport handles auto-auth to router per-role
type KeeneticTransport struct {
	Base http.RoundTripper
}

func (t *KeeneticTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// retrieve role from context
	roleVal := req.Context().Value(roleKey)
	role, _ := roleVal.(string)
	// choose jar
	jarMu.Lock()
	jar := viewerJar
	if role == "Admin" {
		jar = adminJar
	}
	jarMu.Unlock()

	// clone request for safe retry
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body.Close()
	}
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// inject jar cookies
	hostURL := &url.URL{Scheme: cfg.RouterURL.Scheme, Host: cfg.RouterURL.Host}
	for _, c := range jar.Cookies(hostURL) {
		req.AddCookie(c)
	}

	resp, err := t.Base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		// clear jar and re-authenticate
		jarMu.Lock()
		if role == "Admin" {
			adminJar, _ = cookiejar.New(nil)
			jar = adminJar
		} else {
			viewerJar, _ = cookiejar.New(nil)
			jar = viewerJar
		}
		jarMu.Unlock()
		// auth
		if err := authenticateRouter(jar, role); err != nil {
			log.Printf("router auth error: %v", err)
			return nil, fmt.Errorf("router auth failed")
		}
		resp.Body.Close()
		// retry with fresh body and cookies
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		for _, c := range jar.Cookies(hostURL) {
			req.AddCookie(c)
		}
		return t.Base.RoundTrip(req)
	}
	return resp, nil
}

// authenticateRouter logs into router with given jar and role
func authenticateRouter(jar http.CookieJar, role string) error {
	authURL := cfg.RouterURL.ResolveReference(&url.URL{Path: "/auth"})
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	resp, err := client.Get(authURL.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	realm := resp.Header.Get("X-NDM-Realm")
	challenge := resp.Header.Get("X-NDM-Challenge")
	if realm == "" || challenge == "" {
		return errors.New("missing realm or challenge headers")
	}

	// choose credentials by role
	var login, pass string
	if role == "Admin" {
		login, pass = cfg.AdminLogin, cfg.AdminPass
	} else {
		login, pass = cfg.ViewerLogin, cfg.ViewerPass
	}

	// compute hashes
	md5h := md5.New()
	md5h.Write([]byte(login + ":" + realm + ":" + pass))
	md5hex := hex.EncodeToString(md5h.Sum(nil))
	sha := sha256.New()
	sha.Write([]byte(challenge + md5hex))
	shahex := hex.EncodeToString(sha.Sum(nil))

	// post credentials
	creds := map[string]string{"login": login, "password": shahex}
	buf, _ := json.Marshal(creds)
	resp2, err := client.Post(authURL.String(), "application/json", strings.NewReader(string(buf)))
	if err != nil {
		return err
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		return fmt.Errorf("auth failed with status %d", resp2.StatusCode)
	}
	return nil
}
