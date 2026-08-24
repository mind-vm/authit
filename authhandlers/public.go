package authhandlers

import (
	"net/http"
)

func (h *UserHandler) register(w http.ResponseWriter, r *http.Request) {
	req, err := decodeJSON[registerRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	u, err := h.svc.Register(r.Context(), req.Email, req.Password)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, newUserResponse(u))
}

func (h *UserHandler) login(w http.ResponseWriter, r *http.Request) {
	req, err := decodeJSON[loginRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	result, err := h.svc.Authenticate(r.Context(), req.Email, req.Password, r.UserAgent(), h.ip(r))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newLoginResponse(result))
}

func (h *UserHandler) verifyTwoFactorLogin(w http.ResponseWriter, r *http.Request) {
	req, err := decodeJSON[twoFactorLoginRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	result, err := h.svc.VerifyTwoFactorLogin(r.Context(), req.PendingTwoFactorToken, req.Code, r.UserAgent(), h.ip(r))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newLoginResponse(result))
}

func (h *UserHandler) refresh(w http.ResponseWriter, r *http.Request) {
	req, err := decodeJSON[refreshRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	tokens, err := h.svc.Refresh(r.Context(), req.RefreshToken, r.UserAgent(), h.ip(r))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newTokenResponse(tokens))
}

func (h *UserHandler) logout(w http.ResponseWriter, r *http.Request) {
	req, err := decodeJSON[logoutRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := h.svc.Logout(r.Context(), req.RefreshToken); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *UserHandler) requestPasswordReset(w http.ResponseWriter, r *http.Request) {
	req, err := decodeJSON[passwordResetRequestRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := h.svc.RequestPasswordReset(r.Context(), req.Email); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *UserHandler) resetPassword(w http.ResponseWriter, r *http.Request) {
	req, err := decodeJSON[passwordResetRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := h.svc.ResetPassword(r.Context(), req.Token, req.NewPassword); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *UserHandler) verifyEmail(w http.ResponseWriter, r *http.Request) {
	req, err := decodeJSON[emailVerifyRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := h.svc.VerifyEmail(r.Context(), req.Token); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *UserHandler) requestEmailVerificationByEmail(w http.ResponseWriter, r *http.Request) {
	req, err := decodeJSON[emailVerificationRequestByEmailRequest](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := h.svc.RequestEmailVerificationByEmail(r.Context(), req.Email); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
