// Command example runs authit's user plane over plain HTTP, backed by
// memstore, so every flow can be exercised with curl and nothing else
// installed — no database, no config file, no environment variables.
//
// It exists to prove the pieces fit at runtime, which the package tests
// alone don't show: authhandlers mounts on a stdlib ServeMux, user.Service
// drives it, and the store layer behind it is swappable. Swapping memstore
// for sqlbstore is a change to the user.Stores literal in run and nothing
// else — that substitution is the claim authit's design makes, and this is
// the smallest place to watch it hold.
//
// This is a demo, not a deployment. Signing keys are random per boot, all
// state is in memory, and there is no TLS, CORS, or rate limiting. See
// README.md in this directory for a curl walkthrough.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mind-vm/authit/audit"
	"github.com/mind-vm/authit/authhandlers"
	"github.com/mind-vm/authit/authithttp"
	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/memstore"
	"github.com/mind-vm/authit/user"
)

func main() {
	addr := flag.String("addr", ":8080", "address to listen on")
	requireVerification := flag.Bool("require-verification", true,
		"refuse login until the address is verified (authit's own default)")
	flag.Parse()

	if err := run(*addr, *requireVerification); err != nil {
		slog.Error("example server failed", "error", err)
		os.Exit(1)
	}
}

func run(addr string, requireVerification bool) error {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))

	// Random per boot. Restarting invalidates every token already issued,
	// which costs nothing here because memstore has already lost the
	// accounts those tokens refer to.
	jwtSecret, err := randomKey(32)
	if err != nil {
		return fmt.Errorf("generating jwt secret: %w", err)
	}
	totpKey, err := randomKey(32)
	if err != nil {
		return fmt.Errorf("generating totp encryption key: %w", err)
	}

	signer, err := authitjwt.NewHMACSigner(jwtSecret, authitjwt.Defaults{Issuer: "authit-example"})
	if err != nil {
		return fmt.Errorf("building signer: %w", err)
	}

	policy := user.EmailVerificationRequired
	if !requireVerification {
		policy = user.EmailVerificationOptional
	}

	// The swap point. Replace these seven constructors with sqlbstore
	// tables and every line below stays as it is.
	stores := user.Stores{
		Users:              memstore.NewUserStore(),
		RefreshTokens:      memstore.NewRefreshTokenStore(),
		PasswordResets:     memstore.NewPasswordResetStore(),
		EmailVerifications: memstore.NewEmailVerificationStore(),
		TOTP:               memstore.NewTOTPStore(),
		PendingTwoFactor:   memstore.NewPendingTwoFactorStore(),
		Lockouts:           memstore.NewLockoutStore(),
	}

	svc, err := user.NewService(stores, signer, consoleEmailer{}, user.Config{
		TOTPIssuer:        "authit-example",
		TOTPEncryptionKey: totpKey,
		EmailVerification: policy,
		// Opt in so logins, lockouts, and 2FA changes show up in the log
		// while you drive the API — the events are the interesting part.
		AuditLogger: audit.SlogLogger{Logger: slog.Default()},
	})
	if err != nil {
		return fmt.Errorf("building user service: %w", err)
	}

	// authhandlers owns its own subtree and nothing else. Mounting it under
	// a prefix is the host's call, not the package's.
	// Bearer tokens are verified against the same signer that minted them.
	auth := authithttp.VerifierAuth(signer)

	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", authhandlers.NewUserHandler(svc, auth)))
	mux.HandleFunc("/", index)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	slog.Info("authit example listening",
		"addr", addr,
		"routes", "GET / for the route list",
		"email_verification", policyName(policy),
	)

	select {
	case err := <-serveErr:
		return fmt.Errorf("listening on %s: %w", addr, err)
	case <-ctx.Done():
	}

	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// consoleEmailer stands in for real delivery by printing the token to
// stdout. That is what makes password reset and email verification
// curl-able end to end: the token a real user would receive by mail lands
// on the terminal instead. A production host implements this interface
// against its own SMTP or API client.
type consoleEmailer struct{}

func (consoleEmailer) SendPasswordReset(_ context.Context, email, token string) error {
	fmt.Printf("\n  [email] password reset for %s\n          token: %s\n\n", email, token)
	return nil
}

func (consoleEmailer) SendEmailVerification(_ context.Context, email, token string) error {
	fmt.Printf("\n  [email] verify address for %s\n          token: %s\n\n", email, token)
	return nil
}

func index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, routeList)
}

const routeList = `authit example — user plane over plain HTTP, backed by memstore.

Public (no Authorization header):
  POST   /auth/register                          {"email","password"}          -> 201
  POST   /auth/login                             {"email","password"}          -> 200
  POST   /auth/login/two-factor                  {"pending_two_factor_token","code"}
  POST   /auth/refresh                           {"refresh_token"}             -> 200
  POST   /auth/logout                            {"refresh_token"}             -> 204
  POST   /auth/password/reset-request            {"email"}                     -> 204
  POST   /auth/password/reset                    {"token","new_password"}      -> 204
  POST   /auth/email/verify                      {"token"}                     -> 204
  POST   /auth/email/verification-request        {"email"}                     -> 204

Protected (Authorization: Bearer <access_token>):
  POST   /auth/password/change                   {"current_password","new_password"}
  POST   /auth/me/email/verification-request
  GET    /auth/me/sessions
  DELETE /auth/me/sessions/{id}
  POST   /auth/me/sessions/revoke-others         {"current_refresh_token"}
  POST   /auth/me/two-factor/setup
  POST   /auth/me/two-factor/confirm             {"code"}
  POST   /auth/me/two-factor/disable             {"code"}
  POST   /auth/me/two-factor/backup-codes/regenerate  {"code"}
  GET    /auth/me/two-factor

Reset and verification tokens are printed to this server's stdout.
`

func policyName(p user.EmailVerificationPolicy) string {
	if p == user.EmailVerificationOptional {
		return "optional"
	}
	return "required"
}

func randomKey(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
