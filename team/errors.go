package team

import "errors"

var (
	// ErrNotFound is returned when an operation names a team, member or
	// invitation that does not exist. It used to arrive as store.ErrNotFound
	// from whatever the host had implemented; now that the query is authit's
	// own, so is the error.
	ErrNotFound           = errors.New("authit/team: not found")
	ErrInvitationInvalid  = errors.New("authit/team: invitation invalid, expired, or already used")
	ErrEmailMismatch      = errors.New("authit/team: invitation email does not match")
	ErrLastOwner          = errors.New("authit/team: team must have at least one owner")
	ErrNotOwner           = errors.New("authit/team: caller is not an owner")
	ErrMemberNotFound     = errors.New("authit/team: member not found")
	ErrSlugTaken          = errors.New("authit/team: slug already in use")
	ErrMembershipRejected = errors.New("authit/team: membership rejected")
)
