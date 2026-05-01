package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

func runAuth(args []string) {
	fs := flag.NewFlagSet("auth", flag.ExitOnError)
	cfgPath := fs.String("config", "config.yaml", "config file containing oauth integration definitions")
	port := fs.Int("port", 7777, "local callback port")
	noOpen := fs.Bool("no-open", false, "print URL only, don't auto-open browser")
	_ = fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: clawpatrol auth <integration-id> [-config FILE] [-port N] [-no-open]")
		os.Exit(2)
	}
	id := fs.Arg(0)

	cfg, _ := loadConfig(*cfgPath) // config optional for auth flow
	var found *OAuthIntegration
	if cfg != nil {
		for i := range cfg.OAuth {
			if cfg.OAuth[i].ID == id {
				found = &cfg.OAuth[i]
				break
			}
		}
	}
	if found == nil {
		found = defaultOAuthByID(id)
	}
	if found == nil {
		fail("integration %q not found (built-ins: %v)", id, defaultOAuthKeys())
	}

	verifier := randomString(64)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state := randomString(32)

	redirect := found.OAuth.RedirectURI
	pasteMode := redirect != "" && !strings.HasPrefix(redirect, "http://localhost") && !strings.HasPrefix(redirect, "http://127.0.0.1")
	if redirect == "" {
		redirect = fmt.Sprintf("http://localhost:%d/callback", *port)
	}

	o := &oauth2.Config{
		ClientID:     resolveTemplate(found.OAuth.ClientID),
		ClientSecret: resolveTemplate(found.OAuth.ClientSecret),
		Scopes:       found.OAuth.Scopes,
		RedirectURL:  redirect,
		Endpoint: oauth2.Endpoint{
			AuthURL:  found.OAuth.AuthURL,
			TokenURL: found.OAuth.TokenURL,
		},
	}
	url := o.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	if pasteMode {
		fmt.Println(strings.Repeat("─", 60))
		fmt.Printf("OAuth flow for %q (paste mode)\n\n", id)
		if !*noOpen {
			fmt.Println("opening browser. if it doesn't open, paste this URL:")
			_ = openBrowser(url)
		} else {
			fmt.Println("open this URL in your browser:")
		}
		fmt.Println("\n  " + url + "\n")
		fmt.Println(strings.Repeat("─", 60))
		fmt.Print("after authorizing, paste the code from the redirect URL here\n(look for ?code=... in the URL bar): ")
		var code string
		fmt.Scanln(&code)
		code = strings.TrimSpace(code)
		if code == "" {
			fail("empty code")
		}
		exchangeAndReport(o, code, verifier, redirect, id, found.ID)
		return
	}

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	srv := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", *port)}
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		got := r.URL.Query()
		if got.Get("state") != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			errCh <- fmt.Errorf("state mismatch")
			return
		}
		if e := got.Get("error"); e != "" {
			http.Error(w, e+": "+got.Get("error_description"), http.StatusBadRequest)
			errCh <- fmt.Errorf("oauth error: %s", e)
			return
		}
		code := got.Get("code")
		if code == "" {
			http.Error(w, "no code", http.StatusBadRequest)
			errCh <- fmt.Errorf("no code")
			return
		}
		fmt.Fprint(w, "<h2>clawpatrol: authentication received</h2><p>You can close this tab.</p>")
		codeCh <- code
	})
	go func() {
		_ = srv.ListenAndServe()
	}()
	defer srv.Shutdown(context.Background())

	fmt.Println(strings.Repeat("─", 60))
	fmt.Printf("OAuth flow for %q\n\n", id)
	if *noOpen {
		fmt.Println("open this URL in your browser:")
	} else {
		fmt.Println("opening browser. if it doesn't open, paste this URL:")
	}
	fmt.Println("\n  " + url + "\n")
	fmt.Println(strings.Repeat("─", 60))
	if !*noOpen {
		_ = openBrowser(url)
	}

	var code string
	select {
	case code = <-codeCh:
	case e := <-errCh:
		fail("callback: %v", e)
	case <-time.After(5 * time.Minute):
		fail("timeout waiting for callback (5min)")
	}

	exchangeAndReport(o, code, verifier, redirect, id, found.ID)
}

func exchangeAndReport(o *oauth2.Config, code, verifier, redirect, id, _envIDFallback string) {
	tok, err := o.Exchange(context.Background(), code,
		oauth2.SetAuthURLParam("code_verifier", verifier),
		oauth2.SetAuthURLParam("redirect_uri", redirect),
	)
	if err != nil {
		fail("token exchange: %v", err)
	}

	fmt.Println("\n✓ tokens received")
	fmt.Println()
	fmt.Printf("access_token:  %s...%s (expires %s)\n",
		safeHead(tok.AccessToken, 12), safeTail(tok.AccessToken, 6), tok.Expiry.Format(time.RFC3339))
	if tok.RefreshToken != "" {
		fmt.Printf("refresh_token: %s...%s\n", safeHead(tok.RefreshToken, 12), safeTail(tok.RefreshToken, 6))
	}
	fmt.Println()
	envName := strings.ToUpper(strings.ReplaceAll(id, "-", "_")) + "_REFRESH"
	fmt.Println("add to gateway secrets.env (paste this on the gateway host):")
	fmt.Printf("  %s='%s'\n", envName, tok.RefreshToken)
	fmt.Println()
	fmt.Println("then restart gateway: systemctl restart clawpatrol-gateway")
}

func oauthIDs(items []OAuthIntegration) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.ID
	}
	return out
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "linux":
		return exec.Command("xdg-open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	}
	return fmt.Errorf("unknown OS: %s", runtime.GOOS)
}

func randomString(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func safeHead(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
func safeTail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
