package authhandlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/mind-vm/authit/store"
)

// SessionIssuer turns a resolved user into whatever the host hands back,
// and writes the response itself.
//
// Every route group that takes one resolves an identity without minting a
// credential — oidc, passkey and emaillogin all answer "who is this" and
// stop there, the same way pat.Resolve and device.PollDeviceToken do. What
// a signed-in user should receive is the host's decision, so these
// constructors require this and panic without it.
//
// It writes the response rather than returning a body because these flows
// do not agree on what a response is. A passkey assertion is an XHR that
// wants JSON; an OAuth callback is a top-level browser navigation that
// wants a redirect and a Set-Cookie. One signature covers both only if it
// owns the ResponseWriter.
//
// created reports whether this sign-in brought the account into existence,
// so a host can send somewhere different the first time.
//
// Returning an error produces a 500 and nothing else; the response must not
// have been partially written in that case.
type SessionIssuer func(w http.ResponseWriter, r *http.Request, u store.User, created bool) error

func (h *ceremonyBase) issue(w http.ResponseWriter, r *http.Request, u store.User, created bool) {
	if err := h.issuer(w, r, u, created); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
	}
}

// ceremonyBase is the shared state of the three groups that run a
// begin/finish ceremony across a browser round trip.
type ceremonyBase struct {
	issuer SessionIssuer
	// cookiePath scopes the short-lived ceremony cookie to this group's
	// own subtree, so it is not attached to every request to the origin.
	cookiePath string
	insecure   bool
	// key authenticates the ceremony cookie. See WithCeremonyKey.
	key []byte
}

// ceremonyTTL bounds how long a half-finished ceremony stays resumable.
//
// It is short on purpose: the cookie holds the state and PKCE auth, or
// a WebAuthn challenge, and none of those have any reason to outlive the
// user's attention span.
const ceremonyTTL = 10 * time.Minute

// setCeremonyCookie stores opaque ceremony state for the duration of one
// round trip.
//
// sameSite is a parameter rather than a constant because the two flows
// genuinely differ, and getting it wrong fails in opposite ways. A WebAuthn
// ceremony is driven by XHR from your own page, so Strict costs nothing. An
// OAuth callback is a top-level navigation *from the provider*, which is a
// cross-site request — a Strict cookie is not sent with it, and the
// callback then cannot find the state it is supposed to check. Lax is sent
// on top-level navigations and is the weakest setting that works.
func (h *ceremonyBase) setCeremonyCookie(w http.ResponseWriter, name string, value []byte, sameSite http.SameSite) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    base64.RawURLEncoding.EncodeToString(h.sign(name, value)),
		Path:     h.cookiePath,
		MaxAge:   int(ceremonyTTL.Seconds()),
		Secure:   !h.insecure,
		HttpOnly: true,
		SameSite: sameSite,
	})
}

// sign prefixes value with an HMAC over the cookie's name and contents.
//
// The cookie is state the browser holds and hands back, and every flow
// here trusts what comes back: the OAuth state and PKCE verifier the
// callback is checked against, or the WebAuthn challenge the signature is
// checked against. Unauthenticated, that is not storage, it is an input --
// a caller with curl writes whatever it likes into it and the ceremony
// verifies against the attacker's own expectations.
//
// The name is inside the MAC so that a cookie minted for one ceremony
// cannot be presented as another. Registration and login already use
// separate names for that reason; without binding, the names are only a
// convention the client is free to ignore.
func (h *ceremonyBase) sign(name string, value []byte) []byte {
	mac := hmac.New(sha256.New, h.key)
	mac.Write([]byte(name))
	mac.Write([]byte{0})
	mac.Write(value)
	return mac.Sum(value[:len(value):len(value)])
}

// readCeremonyCookie reads ceremony state, rejecting anything this server
// did not sign.
func (h *ceremonyBase) readCeremonyCookie(r *http.Request, name string) ([]byte, bool) {
	c, err := r.Cookie(name)
	if err != nil || c.Value == "" {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || len(raw) <= sha256.Size {
		return nil, false
	}
	value, sum := raw[:len(raw)-sha256.Size], raw[len(raw)-sha256.Size:]
	if !hmac.Equal(sum, h.sign(name, value)[len(value):]) {
		return nil, false
	}
	return value, true
}

// clearCeremonyCookie expires it. The attributes must match the ones it was
// set with or the browser keeps the original — see authithttp's
// ClearRefreshCookie for the same trap.
func (h *ceremonyBase) clearCeremonyCookie(w http.ResponseWriter, name string, sameSite http.SameSite) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: h.cookiePath,
		MaxAge: -1, Expires: time.Unix(0, 0),
		Secure: !h.insecure, HttpOnly: true, SameSite: sameSite,
	})
}

// ceremonyState is what the OAuth cookie carries: two values that must
// survive the trip to the provider and back.
type ceremonyState struct {
	State    string `json:"state"`
	Verifier string `json:"verifier"`
}

func encodeState(s ceremonyState) []byte {
	b, _ := json.Marshal(s)
	return b
}

func decodeState(raw []byte) (ceremonyState, bool) {
	var s ceremonyState
	if err := json.Unmarshal(raw, &s); err != nil || s.State == "" {
		return ceremonyState{}, false
	}
	return s, true
}
