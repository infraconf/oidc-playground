package oidc

import (
	"net/http"

	"github.com/infraconf/oidc-playground/internal/config"
	"github.com/infraconf/oidc-playground/public"
)

type AuthorizeParam struct {
	Name   string
	Value  string
	Status bool
}

type AuthorizeParams struct {
	Name                string `json:"name"`
	ResponseType        string `json:"response_type"`
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}
type AuthorizePageData struct {
	Params []AuthorizeParam `json:"params"`
	Users  []config.User    `json:"users"`
}

func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":       "invalid_request",
			"description": "failed to parse authorize parameters",
		})
		return
	}

	params := AuthorizeParams{
		ResponseType:        r.Form.Get("response_type"),
		ClientID:            r.Form.Get("client_id"),
		RedirectURI:         r.Form.Get("redirect_uri"),
		Scope:               r.Form.Get("scope"),
		State:               r.Form.Get("state"),
		Nonce:               r.Form.Get("nonce"),
		CodeChallenge:       r.Form.Get("code_challenge"),
		CodeChallengeMethod: r.Form.Get("code_challenge_method"),
	}

	paramList := []AuthorizeParam{
		{"Response Type", params.ResponseType, params.ResponseType == "code"},
		{"Client ID", params.ClientID, params.ClientID != ""},
		{"Redirect URI", params.RedirectURI, params.RedirectURI != ""},
		{"Scope", params.Scope, params.Scope != ""},
		{"State", params.State, params.State != ""},
		{"Nonce", params.Nonce, params.Nonce != ""},
		{"Code Challenge", params.CodeChallenge, params.CodeChallenge != ""},
		{"Code Challenge Method", params.CodeChallengeMethod, params.CodeChallengeMethod != ""},
	}

	data := AuthorizePageData{
		Params: paramList,
		Users:  h.config.Users,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := public.RenderAuthorize(w, data); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}
