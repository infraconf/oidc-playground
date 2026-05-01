package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
)

func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeTokenError(w, http.StatusMethodNotAllowed, "invalid_request", "token endpoint only supports POST")
		return
	}

	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "failed to parse token request")
		return
	}

	if grantType := strings.TrimSpace(r.Form.Get("grant_type")); grantType != "authorization_code" {
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
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

	code := strings.TrimSpace(r.Form.Get("code"))
	if code == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "missing authorization code")
		return
	}

	session, ok := h.getCode(code)
	if !ok {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid or expired")
		return
	}

	redirectURI := strings.TrimSpace(r.Form.Get("redirect_uri"))
	if redirectURI == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "missing redirect uri")
		return
	}

	if redirectURI != session.RedirectURI {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "redirect uri does not match authorization request")
		return
	}

	if session.ClientID != clientID {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "authorization code was not issued to this client")
		return
	}

	if err := validateCodeVerifier(r.Form.Get("code_verifier"), session); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}

	session, ok = h.exchangeCode(code)
	if !ok {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid or expired")
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	response := map[string]any{
		"access_token": session.AccessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
	}

	if session.IDToken != "" {
		response["id_token"] = session.IDToken
	}

	writeJSON(w, http.StatusOK, response)
}

func clientCredentials(r *http.Request) (string, string, bool) {
	clientID, clientSecret, ok := r.BasicAuth()
	if ok {
		return strings.TrimSpace(clientID), strings.TrimSpace(clientSecret), true
	}

	clientID = strings.TrimSpace(r.Form.Get("client_id"))
	clientSecret = strings.TrimSpace(r.Form.Get("client_secret"))
	if clientID == "" || clientSecret == "" {
		return "", "", false
	}

	return clientID, clientSecret, true
}

func validateCodeVerifier(rawVerifier string, session *Session) error {
	if session.CodeChallenge == "" {
		return nil
	}

	verifier := strings.TrimSpace(rawVerifier)
	if verifier == "" {
		return invalidGrantError("missing code verifier")
	}

	if !isValidCodeChallenge(verifier) {
		return invalidGrantError("invalid code verifier")
	}

	if session.CodeChallengeMethod != "S256" {
		return invalidGrantError("unsupported code challenge method")
	}

	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if challenge != session.CodeChallenge {
		return invalidGrantError("code verifier does not match code challenge")
	}

	return nil
}

type invalidGrantError string

func (e invalidGrantError) Error() string {
	return string(e)
}
