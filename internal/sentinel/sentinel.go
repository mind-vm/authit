// Package sentinel holds the error class every plane's ErrInvalidToken
// belongs to.
//
// A plane's ErrInvalidToken has to stay its own value, so that
// errors.Is(err, user.ErrInvalidToken) keeps meaning exactly what it always
// did, and keep its own message. It also has to match
// authithttp.ErrInvalidToken, so that a host handing it to
// authithttp.StatusFor gets a 401 rather than a 500. errors.New gives the
// first and fmt.Errorf("%w") changes the message; New gives both.
//
// The class lives here rather than in authithttp so that the planes can
// join it without importing net/http: pat, emaillogin and the rest have no
// notion of HTTP, and should not acquire one for the sake of an error.
package sentinel

import "errors"

// InvalidToken is the class. authithttp exports this exact value as
// ErrInvalidToken, which is why its message names that package.
var InvalidToken = errors.New("authit/http: invalid bearer token")

// New returns an error whose message is msg and which also matches parent
// under errors.Is and errors.As. Each call returns a distinct value, so
// comparing against the result, by == or errors.Is, still works.
func New(msg string, parent error) error {
	return &sentinel{msg: msg, parent: parent}
}

type sentinel struct {
	msg    string
	parent error
}

func (e *sentinel) Error() string { return e.msg }
func (e *sentinel) Unwrap() error { return e.parent }
