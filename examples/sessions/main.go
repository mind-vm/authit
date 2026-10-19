// Command sessions is a small web application signed in by cookie
// sessions: user.SessionModeOpaque over sqlitestore, guarded by
// authithttp.SessionMiddleware and authithttp.CSRFProtect.
//
//	go run ./examples/sessions -addr 127.0.0.1:8080 -db /tmp/sessions.db
//
// It serves plain HTTP, for trying it out locally, which is why the cookies
// are configured with AllowHTTP. Behind a TLS-terminating proxy, drop
// AllowHTTP (the cookies are then always Secure) or set TrustForwardedProto
// if the proxy sets X-Forwarded-Proto.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"html/template"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/mind-vm/authit/authithttp"
	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/sqlitestore"
	"github.com/mind-vm/authit/user"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	dbPath := flag.String("db", "sessions-example.db", "SQLite database file")
	flag.Parse()

	ctx := context.Background()
	app, err := newApp(ctx, *dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer app.Close()
	log.Printf("listening on http://%s", *addr)
	log.Fatal(http.ListenAndServe(*addr, app.Handler()))
}

// sessionTTL is both the server-side session lifetime and the cookie's, so
// the browser keeps the cookie as long as the session lives.
const sessionTTL = 7 * 24 * time.Hour

type app struct {
	db     *sqlitestore.Store
	users  *user.Service
	cookie authithttp.SessionCookieOptions
}

func newApp(ctx context.Context, dbPath string) (*app, error) {
	db, err := sqlitestore.Open(ctx, dbPath)
	if err != nil {
		return nil, err
	}
	// Opaque mode never signs anything, but the service is built around a
	// signer, so it gets a throwaway one.
	signer, err := authitjwt.NewHMACSigner([]byte(rand.Text()+rand.Text()), authitjwt.Defaults{Issuer: "sessions-example"})
	if err != nil {
		db.Close()
		return nil, err
	}
	users, err := user.NewService(user.Stores{
		Users: db, RefreshTokens: db, PasswordResets: db, EmailVerifications: db,
		TOTP: db, PendingTwoFactor: db, Lockouts: db, Tx: db,
	}, signer, nil, user.Config{
		SessionMode:     user.SessionModeOpaque,
		RefreshTokenTTL: sessionTTL,
		// There is no mail in this example, so nobody could verify.
		EmailVerification: user.EmailVerificationOptional,
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &app{
		db:     db,
		users:  users,
		cookie: authithttp.SessionCookieOptions{MaxAge: sessionTTL, AllowHTTP: true},
	}, nil
}

func (a *app) Close() error { return a.db.Close() }

// Handler is the whole application. CSRFProtect wraps everything, so no
// form can be posted from another site; SessionMiddleware wraps the pages
// that need someone signed in, and, with Optional, the home page, which
// only wants to know.
func (a *app) Handler() http.Handler {
	required, err := authithttp.SessionMiddleware(a.users, authithttp.SessionOptions{
		Cookie: a.cookie, SignInURL: "/signin",
	})
	if err != nil {
		panic(err)
	}
	optional, err := authithttp.SessionMiddleware(a.users, authithttp.SessionOptions{
		Cookie: a.cookie, Optional: true,
	})
	if err != nil {
		panic(err)
	}
	csrf, err := authithttp.CSRFProtect(authithttp.CSRFOptions{
		DoubleSubmit: true,
		TokenCookie:  authithttp.SessionCookieOptions{AllowHTTP: true},
	})
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /{$}", optional(http.HandlerFunc(a.home)))
	mux.HandleFunc("GET /signin", a.signInForm)
	mux.HandleFunc("POST /signin", a.signIn)
	mux.HandleFunc("POST /register", a.register)
	mux.Handle("GET /account", required(http.HandlerFunc(a.account)))
	mux.Handle("POST /signout", required(http.HandlerFunc(a.signOut)))
	return csrf(mux)
}

var page = template.Must(template.New("page").Parse(`<!doctype html>
<title>authit sessions example</title>
{{if .Email}}<p>Signed in as {{.Email}}.</p>
<form method="post" action="/signout"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><button>Sign out</button></form>
<p><a href="/account">Account</a></p>
{{else}}{{if .Error}}<p>{{.Error}}</p>{{end}}
<form method="post" action="/signin">
<input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="next" value="{{.Next}}">
<input name="email" type="email" placeholder="email"> <input name="password" type="password" placeholder="password">
<button>Sign in</button> <button formaction="/register">Register</button>
</form>{{end}}
`))

type view struct {
	Email, CSRF, Next, Error string
}

func (a *app) render(w http.ResponseWriter, r *http.Request, v view) {
	v.CSRF = authithttp.CSRFToken(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := page.Execute(w, v); err != nil {
		log.Printf("render: %v", err)
	}
}

func (a *app) home(w http.ResponseWriter, r *http.Request) {
	claims, _ := authithttp.ClaimsFrom(r.Context())
	a.render(w, r, view{Email: claims.Email})
}

func (a *app) signInForm(w http.ResponseWriter, r *http.Request) {
	a.render(w, r, view{Next: authithttp.SafeReturnTo(r.URL.Query().Get("next"), "/")})
}

func (a *app) account(w http.ResponseWriter, r *http.Request) {
	claims, _ := authithttp.ClaimsFrom(r.Context())
	a.render(w, r, view{Email: claims.Email})
}

func (a *app) register(w http.ResponseWriter, r *http.Request) {
	if _, err := a.users.Register(r.Context(), r.PostFormValue("email"), r.PostFormValue("password")); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		a.render(w, r, view{Error: "Could not register: " + err.Error()})
		return
	}
	a.signIn(w, r)
}

func (a *app) signIn(w http.ResponseWriter, r *http.Request) {
	res, err := a.users.Authenticate(r.Context(), r.PostFormValue("email"), r.PostFormValue("password"),
		r.UserAgent(), clientIP(r))
	if err != nil || res.Tokens == nil {
		// RequiresTwoFactor lands here too; this example has no 2FA page.
		status := http.StatusUnauthorized
		if err != nil && !errors.Is(err, user.ErrInvalidCredentials) && !errors.Is(err, user.ErrAccountLocked) {
			status = http.StatusInternalServerError
		}
		w.WriteHeader(status)
		a.render(w, r, view{Error: "Sign-in failed.", Next: r.PostFormValue("next")})
		return
	}
	if err := authithttp.SetSessionCookie(w, r, res.Tokens.AccessToken, a.cookie); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, authithttp.SafeReturnTo(r.PostFormValue("next"), "/"), http.StatusSeeOther)
}

func (a *app) signOut(w http.ResponseWriter, r *http.Request) {
	if token, ok := authithttp.SessionCookie(r, a.cookie); ok {
		if err := a.users.Logout(r.Context(), token); err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
	_ = authithttp.ClearSessionCookie(w, r, a.cookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
