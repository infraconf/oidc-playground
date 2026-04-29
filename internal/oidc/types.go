package oidc

import (
	"encoding/json"
	"time"

	"github.com/infraconf/oidc-playground/internal/config"
)

type Session struct {
	AccessToken    string
	IDToken        string
	UserInfo       json.RawMessage
	ClientID       string
	CodeExpireTime time.Time
}

type IDToken struct {
	Issuer            string `json:"iss"`
	Subject           string `json:"sub"`
	Audience          string `json:"aud"`
	ExpirationTime    int    `json:"exp"`
	IssuedAt          int    `json:"iat"`
	AuthTime          int    `json:"auth_time"`
	Nonce             string `json:"nonce,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`

	Email         string `json:"email,omitempty"`
	EmailVerified *bool  `json:"email_verified,omitempty"`

	Name      string    `json:"name,omitempty"`
	GivenName string    `json:"given_name,omitempty"`
	Nickname  string    `json:"nickname,omitempty"`
	Groups    *[]string `json:"groups,omitempty"`

	Extras map[string]any `json:"-"`
}

func (t IDToken) MarshalJSON() ([]byte, error) {
	type Alias IDToken
	data := map[string]any{}
	b, err := json.Marshal(struct {
		Alias
	}{
		Alias: Alias(t),
	})
	if err != nil {
		return nil, err
	}
	json.Unmarshal(b, &data)

	if t.Extras != nil {
		for k, v := range t.Extras {
			data[k] = v
		}
	}

	return json.Marshal(data)
}

type AuthorizationRequestParameter struct {
	Name   string
	Value  string
	Status bool
}

type AuthorizeParams struct {
	ResponseType        string   `json:"response_type"`
	ClientID            string   `json:"client_id"`
	RedirectURI         string   `json:"redirect_uri"`
	Scope               string   `json:"scope"`
	State               string   `json:"state"`
	Nonce               string   `json:"nonce"`
	CodeChallenge       string   `json:"code_challenge"`
	CodeChallengeMethod string   `json:"code_challenge_method"`
	TargetUser          string   `json:"-"`
	Options             []string `json:"-"`
}

type AuthorizationPageModel struct {
	Users        []config.User   `json:"users"`
	Params       AuthorizeParams `json:"params"`
	ErrorMessage string          `json:"error_message"`
}

type AuthorizationPageData struct {
	Params                 []AuthorizationRequestParameter
	Users                  []config.User
	AuthorizationPageModel string
}
