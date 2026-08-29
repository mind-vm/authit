package authhandlers

import (
	"context"
	"errors"
	"github.com/mind-vm/authit/authithttp"
	"net/http"
	"time"

	authitjwt "github.com/mind-vm/authit/jwt"
	"github.com/mind-vm/authit/store"
	"github.com/mind-vm/authit/team"
)

// ErrForbidden is what a TeamAuthorizer returns to deny an operation. It
// maps to 403.
var ErrForbidden = errors.New("authit/authhandlers: forbidden")

// TeamAction names what a team route is about to do, so a TeamAuthorizer
// can decide without knowing about HTTP.
type TeamAction string

const (
	// TeamActionView covers reading a team and its membership.
	TeamActionView TeamAction = "view"
	// TeamActionManageMembers covers changing roles, activating and
	// deactivating members, and removing them.
	TeamActionManageMembers TeamAction = "manage_members"
	// TeamActionManageInvitations covers creating, listing and revoking
	// invitations.
	TeamActionManageInvitations TeamAction = "manage_invitations"
	// TeamActionManageOwners covers granting the owner role, and
	// mutating a member who already holds it.
	//
	// It is separate from TeamActionManageMembers because owner is the one
	// role authit itself gives meaning to: the last-owner guards in the
	// team package are the only invariant the library enforces about who
	// controls a team. An authorizer that grants member management to
	// admins is granting the power to add and remove colleagues; it is not
	// necessarily granting the power to become the owner and evict the
	// founder, and before this action existed it could not tell the two
	// apart.
	//
	// A TeamAuthorizer written before this constant will fall to its
	// default case and deny, which is the safe direction.
	TeamActionManageOwners TeamAction = "manage_owners"
)

// TeamAuthorizer decides whether a caller may perform an action on a team.
// Returning a non-nil error denies it; ErrForbidden becomes a 403 and
// anything else a 500.
//
// This exists because the team package deliberately does not check the
// caller's own role -- it says so at length -- and a route group that only
// verified "is this request authenticated" would therefore let any user
// change any member's role in any team. Somebody has to make that
// decision, and over HTTP it cannot be nobody.
type TeamAuthorizer interface {
	Authorize(ctx context.Context, callerUserID, teamID string, action TeamAction) error
}

// RoleAuthorizer implements the conventional rules: an active member may
// view; an active owner or admin may manage members and invitations.
//
// It is offered, not assumed. If your model has a principal that spans
// teams -- a support engineer, a platform auditor -- that identity has no
// home in team.Role by design, and this authorizer will refuse it. Write
// your own that consults your own schema first and falls back to this.
type RoleAuthorizer struct {
	Teams *team.Service
}

func (a RoleAuthorizer) Authorize(ctx context.Context, callerUserID, teamID string, action TeamAction) error {
	m, err := a.Teams.GetMemberByUserAndTeam(ctx, callerUserID, teamID)
	if err != nil {
		// Includes "not a member". Denied either way, and reported the
		// same way, so this cannot be used to discover which teams exist.
		return ErrForbidden
	}
	if !m.IsActive {
		return ErrForbidden
	}
	switch action {
	case TeamActionView:
		return nil
	case TeamActionManageMembers, TeamActionManageInvitations:
		if m.Role == store.RoleOwner || m.Role == store.RoleAdmin {
			return nil
		}
		return ErrForbidden
	case TeamActionManageOwners:
		// Owners only. An admin who could grant this role could grant it
		// to themselves and then remove the owner -- the last-owner guard
		// stops the removal only while one owner remains, and a
		// self-promotion is what supplies the second.
		if m.Role == store.RoleOwner {
			return nil
		}
		return ErrForbidden
	default:
		// Default deny. A new TeamAction must be granted explicitly, so
		// adding one cannot silently open a route.
		return ErrForbidden
	}
}

// TeamHandler serves authit's team plane.
type TeamHandler struct {
	svc   *team.Service
	auth  authithttp.Authenticator
	authz TeamAuthorizer
}

// NewTeamHandler builds the team-plane route group. Every route is
// protected, and every route that touches a specific team consults authz
// first.
//
// authz must not be nil -- NewTeamHandler panics if it is, at startup
// rather than at the first unauthorized request. Pass
// RoleAuthorizer{Teams: svc} for the conventional owner/admin rules, or
// your own implementation.
//
//	POST   /teams
//	GET    /teams/{id}
//	GET    /teams/by-slug?slug=...
//	GET    /teams/{id}/members
//	GET    /me/memberships
//	PATCH  /members/{id}/role
//	PATCH  /members/{id}/active
//	DELETE /members/{id}
//	POST   /teams/{id}/invitations
//	GET    /teams/{id}/invitations
//	DELETE /teams/{id}/invitations/{invitationID}
//	POST   /invitations/lookup
//	POST   /invitations/accept
func NewTeamHandler(svc *team.Service, auth authithttp.Authenticator, authz TeamAuthorizer) http.Handler {
	if authz == nil {
		panic("authit/authhandlers: NewTeamHandler requires a TeamAuthorizer; " +
			"pass RoleAuthorizer{Teams: svc} for the conventional owner/admin rules")
	}
	h := &TeamHandler{svc: svc, auth: auth, authz: authz}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /teams", h.withAuth(h.createTeam))
	mux.HandleFunc("GET /teams/{id}", h.withAuth(h.getTeam))
	// A literal segment rather than "/teams/by-slug/{slug}": that pattern
	// and "/teams/{id}/members" are ambiguous to ServeMux, since {id} could
	// be "by-slug". A literal two-segment path beats "/teams/{id}" cleanly.
	mux.HandleFunc("GET /teams/by-slug", h.withAuth(h.getTeamBySlug))
	mux.HandleFunc("GET /teams/{id}/members", h.withAuth(h.listMembers))
	mux.HandleFunc("GET /me/memberships", h.withAuth(h.listMemberships))
	mux.HandleFunc("PATCH /members/{id}/role", h.withAuth(h.updateMemberRole))
	mux.HandleFunc("PATCH /members/{id}/active", h.withAuth(h.setMemberActive))
	mux.HandleFunc("DELETE /members/{id}", h.withAuth(h.removeMember))
	mux.HandleFunc("POST /teams/{id}/invitations", h.withAuth(h.createInvitation))
	mux.HandleFunc("GET /teams/{id}/invitations", h.withAuth(h.listInvitations))
	mux.HandleFunc("DELETE /teams/{id}/invitations/{invitationID}", h.withAuth(h.revokeInvitation))
	mux.HandleFunc("POST /invitations/lookup", h.withAuth(h.lookupInvitation))
	mux.HandleFunc("POST /invitations/accept", h.withAuth(h.acceptInvitation))
	return mux
}

func (h *TeamHandler) withAuth(next authedHandlerFunc) http.HandlerFunc {
	return requireUser(h.auth, next)
}

// authorize consults the TeamAuthorizer and writes the response itself on
// denial, returning false so the caller can simply return.
func (h *TeamHandler) authorize(w http.ResponseWriter, r *http.Request, callerUserID, teamID string, action TeamAction) bool {
	err := h.authz.Authorize(r.Context(), callerUserID, teamID, action)
	if err == nil {
		return true
	}
	if errors.Is(err, ErrForbidden) {
		writeError(w, http.StatusForbidden, "forbidden", ErrForbidden.Error())
		return false
	}
	// The authorizer itself failed -- a storage error, say. Refusing with
	// 500 rather than 403 keeps "denied" meaningful.
	writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
	return false
}

// memberTeam resolves a member id to its team, so a member-scoped route is
// authorized against the team the member actually belongs to rather than
// one the caller names.
func (h *TeamHandler) memberTeam(w http.ResponseWriter, r *http.Request, memberID string) (store.Member, bool) {
	m, err := h.svc.GetMember(r.Context(), memberID)
	if err != nil {
		writeServiceError(w, err)
		return store.Member{}, false
	}
	return m, true
}

func (h *TeamHandler) createTeam(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	req, err := decodeJSON[createTeamRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	// The owner is the caller, and their email comes from the validated
	// token rather than the request body. Taking it from the body would
	// let a caller stamp somebody else's address on their member record.
	t, err := h.svc.CreateTeam(r.Context(), req.Name, req.Slug, claims.Subject, req.DisplayName, claims.Email)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, newTeamResponse(t))
}

func (h *TeamHandler) getTeam(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	id := r.PathValue("id")
	if !h.authorize(w, r, claims.Subject, id, TeamActionView) {
		return
	}
	t, err := h.svc.GetTeam(r.Context(), id)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newTeamResponse(t))
}

func (h *TeamHandler) getTeamBySlug(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	slug := r.URL.Query().Get("slug")
	if slug == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "slug query parameter is required")
		return
	}
	t, err := h.svc.GetTeamBySlug(r.Context(), slug)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	// Authorized after the lookup, because the slug has to be resolved to
	// an id first -- but the response is still gated, so this is not a way
	// to read a team you cannot see.
	if !h.authorize(w, r, claims.Subject, t.ID, TeamActionView) {
		return
	}
	writeJSON(w, http.StatusOK, newTeamResponse(t))
}

func (h *TeamHandler) listMembers(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	id := r.PathValue("id")
	if !h.authorize(w, r, claims.Subject, id, TeamActionView) {
		return
	}
	members, err := h.svc.ListMembersByTeam(r.Context(), id)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	out := make([]memberResponse, len(members))
	for i, m := range members {
		out[i] = newMemberResponse(m)
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *TeamHandler) listMemberships(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	// No authorization step: this returns only the caller's own
	// memberships, which is exactly what the token already establishes.
	members, err := h.svc.ListMembershipsByUser(r.Context(), claims.Subject)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	out := make([]memberResponse, len(members))
	for i, m := range members {
		out[i] = newMemberResponse(m)
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *TeamHandler) updateMemberRole(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	req, err := decodeJSON[updateMemberRoleRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	m, ok := h.memberTeam(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	if !h.authorize(w, r, claims.Subject, m.TeamID, TeamActionManageMembers) {
		return
	}
	// Granting owner, or touching someone who already is one, is a
	// separate decision from ordinary member management. Both directions
	// are checked: the grant is what manufactures a second owner, and the
	// demotion is how the first one is disposed of afterwards.
	if (store.Role(req.Role) == store.RoleOwner || m.Role == store.RoleOwner) &&
		!h.authorize(w, r, claims.Subject, m.TeamID, TeamActionManageOwners) {
		return
	}
	if err := h.svc.UpdateMemberRole(r.Context(), m.ID, store.Role(req.Role)); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *TeamHandler) setMemberActive(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	req, err := decodeJSON[setMemberActiveRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	m, ok := h.memberTeam(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	if !h.authorize(w, r, claims.Subject, m.TeamID, TeamActionManageMembers) {
		return
	}
	if m.Role == store.RoleOwner && !h.authorize(w, r, claims.Subject, m.TeamID, TeamActionManageOwners) {
		return
	}
	if err := h.svc.SetMemberActive(r.Context(), m.ID, req.IsActive); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *TeamHandler) removeMember(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	m, ok := h.memberTeam(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	if !h.authorize(w, r, claims.Subject, m.TeamID, TeamActionManageMembers) {
		return
	}
	if m.Role == store.RoleOwner && !h.authorize(w, r, claims.Subject, m.TeamID, TeamActionManageOwners) {
		return
	}
	if err := h.svc.RemoveMember(r.Context(), m.ID); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *TeamHandler) createInvitation(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	req, err := decodeJSON[createInvitationRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	teamID := r.PathValue("id")
	if !h.authorize(w, r, claims.Subject, teamID, TeamActionManageInvitations) {
		return
	}
	// An invitation carries a role, and AcceptInvitation copies it onto
	// the new member verbatim. Gating only the role route would leave the
	// same grant available to anyone with a second email address.
	if store.Role(req.Role) == store.RoleOwner &&
		!h.authorize(w, r, claims.Subject, teamID, TeamActionManageOwners) {
		return
	}
	// invitedByMemberID must be the caller's own membership in this team,
	// resolved here rather than accepted from the body.
	inviter, err := h.svc.GetMemberByUserAndTeam(r.Context(), claims.Subject, teamID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	token, inv, err := h.svc.CreateInvitation(r.Context(), teamID, inviter.ID, req.Email, store.Role(req.Role))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	// The raw token is returned once. A host that emails the invitation
	// itself should drop it from its own response rather than forwarding
	// it to the browser.
	writeJSON(w, http.StatusCreated, createInvitationResponse{
		Token:      token,
		Invitation: newInvitationResponse(inv),
	})
}

func (h *TeamHandler) listInvitations(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	teamID := r.PathValue("id")
	if !h.authorize(w, r, claims.Subject, teamID, TeamActionManageInvitations) {
		return
	}
	invs, err := h.svc.ListInvitationsByTeam(r.Context(), teamID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	out := make([]invitationResponse, len(invs))
	for i, inv := range invs {
		out[i] = newInvitationResponse(inv)
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *TeamHandler) revokeInvitation(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	teamID := r.PathValue("id")
	invitationID := r.PathValue("invitationID")
	if !h.authorize(w, r, claims.Subject, teamID, TeamActionManageInvitations) {
		return
	}
	// The invitation id is confirmed to belong to the team named in the
	// path before revoking it. Without this, an admin of one team could
	// revoke another team's invitation by putting their own team in the
	// URL -- the authorization above would pass, and RevokeInvitation takes
	// only the id.
	//
	// It is a scan because team.Service exposes no GetInvitation(id);
	// invitation lists are small, and correctness beats the round trip.
	invs, err := h.svc.ListInvitationsByTeam(r.Context(), teamID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	found := false
	for _, inv := range invs {
		if inv.ID == invitationID {
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "invitation_invalid", team.ErrInvitationInvalid.Error())
		return
	}
	if err := h.svc.RevokeInvitation(r.Context(), invitationID); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *TeamHandler) lookupInvitation(w http.ResponseWriter, r *http.Request, _ authitjwt.Claims) {
	req, err := decodeJSON[invitationTokenRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	// POST rather than GET, with the token in the body: a raw invitation
	// token in a URL ends up in access logs, browser history and Referer
	// headers.
	inv, err := h.svc.GetInvitationByToken(r.Context(), req.Token)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newInvitationResponse(inv))
}

func (h *TeamHandler) acceptInvitation(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	req, err := decodeJSON[acceptInvitationRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	// The email comes from the validated token, never the request body.
	// team.AcceptInvitation refuses when it does not match the invitation,
	// and that check is the only thing binding an invitation to its
	// intended recipient -- letting the client supply the address would
	// make it self-attested, and the check worthless.
	m, err := h.svc.AcceptInvitation(r.Context(), req.Token, claims.Subject, claims.Email, req.DisplayName)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newMemberResponse(m))
}

type teamResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	OwnerID   string    `json:"owner_id"`
	CreatedAt time.Time `json:"created_at"`
}

func newTeamResponse(t store.Team) teamResponse {
	return teamResponse{ID: t.ID, Name: t.Name, Slug: t.Slug, OwnerID: t.OwnerID, CreatedAt: t.CreatedAt}
}

type memberResponse struct {
	ID          string    `json:"id"`
	TeamID      string    `json:"team_id"`
	UserID      *string   `json:"user_id,omitempty"`
	Role        string    `json:"role"`
	DisplayName string    `json:"display_name"`
	Email       string    `json:"email"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
}

func newMemberResponse(m store.Member) memberResponse {
	return memberResponse{
		ID: m.ID, TeamID: m.TeamID, UserID: m.UserID, Role: string(m.Role),
		DisplayName: m.DisplayName, Email: m.Email, IsActive: m.IsActive, CreatedAt: m.CreatedAt,
	}
}

// invitationResponse never exposes store.Invitation.TokenHash.
type invitationResponse struct {
	ID          string     `json:"id"`
	TeamID      string     `json:"team_id"`
	Email       string     `json:"email"`
	Role        string     `json:"role"`
	Status      string     `json:"status"`
	InvitedByID string     `json:"invited_by_id"`
	ExpiresAt   time.Time  `json:"expires_at"`
	AcceptedAt  *time.Time `json:"accepted_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

func newInvitationResponse(i store.Invitation) invitationResponse {
	return invitationResponse{
		ID: i.ID, TeamID: i.TeamID, Email: i.Email, Role: string(i.Role),
		Status: string(i.Status), InvitedByID: i.InvitedByID,
		ExpiresAt: i.ExpiresAt, AcceptedAt: i.AcceptedAt, CreatedAt: i.CreatedAt,
	}
}

type createTeamRequest struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
}

type updateMemberRoleRequest struct {
	Role string `json:"role"`
}

type setMemberActiveRequest struct {
	IsActive bool `json:"is_active"`
}

type createInvitationRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

type createInvitationResponse struct {
	// Token is the raw invitation token, returned once.
	Token      string             `json:"token"`
	Invitation invitationResponse `json:"invitation"`
}

type invitationTokenRequest struct {
	Token string `json:"token"`
}

type acceptInvitationRequest struct {
	Token       string `json:"token"`
	DisplayName string `json:"display_name"`
}
