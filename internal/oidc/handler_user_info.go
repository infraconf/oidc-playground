package oidc

import (
	"net/http"
	"strings"
)

func (h *Handler) UserInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeTokenError(w, http.StatusMethodNotAllowed, "invalid_request", "userinfo endpoint only supports GET and POST")
		return
	}

	accessToken, ok := bearerToken(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeTokenError(w, http.StatusUnauthorized, "invalid_token", "missing bearer token")
		return
	}

	session, ok := h.getSession(accessToken)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeTokenError(w, http.StatusUnauthorized, "invalid_token", "access token is invalid")
		return
	}

	if len(session.UserInfo) == 0 {
		writeTokenError(w, http.StatusForbidden, "insufficient_scope", "user info is not available for this token")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(session.UserInfo)
}

func bearerToken(r *http.Request) (string, bool) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(header, "Bearer ") {
		return "", false
	}

	token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	if token == "" {
		return "", false
	}

	return token, true
}
