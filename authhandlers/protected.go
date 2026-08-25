package authhandlers

import (
	"net/http"

	authitjwt "github.com/mind-vm/authit/jwt"
)

func (h *UserHandler) changePassword(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	req, err := decodeJSON[changePasswordRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := h.svc.ChangePassword(r.Context(), claims.Subject, req.CurrentPassword, req.NewPassword); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *UserHandler) requestEmailVerification(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	if err := h.svc.RequestEmailVerification(r.Context(), claims.Subject); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *UserHandler) listSessions(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	sessions, err := h.svc.ListSessions(r.Context(), claims.Subject, r.URL.Query().Get("current_refresh_token"))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	out := make([]sessionResponse, len(sessions))
	for i, s := range sessions {
		out[i] = newSessionResponse(s)
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *UserHandler) revokeSession(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	sessionID := r.PathValue("id")
	if err := h.svc.RevokeSession(r.Context(), claims.Subject, sessionID); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *UserHandler) revokeOtherSessions(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	req, err := decodeJSON[revokeOtherSessionsRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := h.svc.RevokeOtherSessions(r.Context(), claims.Subject, req.CurrentRefreshToken); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *UserHandler) beginTwoFactorSetup(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	setup, err := h.svc.BeginTwoFactorSetup(r.Context(), claims.Subject, claims.Email)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, twoFactorSetupResponse{Secret: setup.Secret, OTPAuthURL: setup.OTPAuthURL})
}

func (h *UserHandler) confirmTwoFactorSetup(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	req, err := decodeJSON[twoFactorCodeRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	enrollment, err := h.svc.ConfirmTwoFactorSetup(r.Context(), claims.Subject, req.Code)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, twoFactorEnrollmentResponse{BackupCodes: enrollment.BackupCodes})
}

func (h *UserHandler) disableTwoFactor(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	req, err := decodeJSON[twoFactorCodeRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := h.svc.DisableTwoFactor(r.Context(), claims.Subject, req.Code); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *UserHandler) regenerateBackupCodes(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	req, err := decodeJSON[twoFactorCodeRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	codes, err := h.svc.RegenerateBackupCodes(r.Context(), claims.Subject, req.Code)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, twoFactorEnrollmentResponse{BackupCodes: codes})
}

func (h *UserHandler) twoFactorStatus(w http.ResponseWriter, r *http.Request, claims authitjwt.Claims) {
	status, err := h.svc.TwoFactorStatus(r.Context(), claims.Subject)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newTwoFactorStatusResponse(status))
}
