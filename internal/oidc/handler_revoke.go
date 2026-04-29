package oidc

import (
	"net/http"
	"strings"
)

func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeTokenError(w, http.StatusMethodNotAllowed, "invalid_request", "revocation endpoint only supports POST")
		return
	}

	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "failed to parse revocation request")
		return
	}

	clientID, clientSecret, ok := clientCredentials(r)
	if !ok {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "missing client authentication")
		return
	}

	client := findClient(h.config.Clients, clientID)
	if client == nil || client.ClientSecret != clientSecret {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}

	token := strings.TrimSpace(r.Form.Get("token"))
	if token == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "missing token")
		return
	}

	tokenTypeHint := strings.TrimSpace(r.Form.Get("token_type_hint"))
	if tokenTypeHint != "" && tokenTypeHint != "access_token" {
		writeTokenError(w, http.StatusBadRequest, "unsupported_token_type", "only access_token is supported")
		return
	}

	h.revokeSession(token, clientID)
	w.WriteHeader(http.StatusOK)
}
