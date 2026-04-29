package oidc

import "net/http"

func (h *Handler) Discovery(w http.ResponseWriter, r *http.Request) {
	issuer := h.issuer(r)

	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/connect/authorize",
		"token_endpoint":                        issuer + "/connect/token",
		"userinfo_endpoint":                     issuer + "/connect/userinfo",
		"revocation_endpoint":                   issuer + "/connect/revoke",
		"jwks_uri":                              issuer + "/connect/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"scopes_supported":                      []string{"openid", "profile", "email", "groups"},
		"claims_supported":                      []string{"sub", "email", "groups"},
	})
}
