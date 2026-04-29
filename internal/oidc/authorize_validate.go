package oidc

import (
	"net/url"
	"slices"
	"strings"

	"github.com/infraconf/oidc-playground/internal/config"
)

type authorizeValidation struct {
	params       *AuthorizeParams
	client       *config.Client
	scopes       []string
	options      []string
	targetUser   *config.User
	errorMessage string
}

var supportedAuthorizeOptions = []string{"full-id-token"}

func normalizeScopes(value string) string {
	return strings.Join(splitParameterList(value), ",")
}

func validateAuthorizeParams(cfg *config.Config, params *AuthorizeParams) authorizeValidation {
	client := findClient(cfg.Clients, params.ClientID)
	validation := authorizeValidation{
		params:  params,
		client:  client,
		scopes:  splitParameterList(params.Scope),
		options: params.Options,
	}

	switch {
	case params.ResponseType == "":
		validation.errorMessage = "missing response_type"
	case params.ResponseType != "code":
		validation.errorMessage = "only response type 'code' is supported"
	case params.ClientID == "":
		validation.errorMessage = "missing client id"
	case client == nil:
		validation.errorMessage = "unknown client id"
	case params.RedirectURI == "":
		validation.errorMessage = "missing redirect uri"
	case !isValidRedirectURI(params.RedirectURI):
		validation.errorMessage = "invalid redirect uri"
	case !isAllowedRedirectURI(client, params.RedirectURI):
		validation.errorMessage = "redirect uri is not registered for client"
	case len(validation.scopes) == 0:
		validation.errorMessage = "missing scope"
	case params.CodeChallenge != "" && !isValidCodeChallenge(params.CodeChallenge):
		validation.errorMessage = "invalid code challenge"
	case params.CodeChallengeMethod != "" && params.CodeChallengeMethod != "S256":
		validation.errorMessage = "only code challenge method 'S256' is supported"
	case params.CodeChallengeMethod != "" && params.CodeChallenge == "":
		validation.errorMessage = "code challenge method requires code challenge"
	case params.CodeChallenge != "" && params.CodeChallengeMethod == "":
		validation.errorMessage = "code challenge requires code challenge method"
	case hasUnsupportedValue(validation.options, supportedAuthorizeOptions):
		validation.errorMessage = "unsupported authorize option"
	}

	if validation.errorMessage != "" || params.TargetUser == "" {
		return validation
	}

	if len(cfg.Users) == 0 {
		validation.errorMessage = "no users configured"
		return validation
	}

	validation.targetUser = findUser(cfg.Users, params.TargetUser)
	if validation.targetUser == nil {
		validation.errorMessage = "unknown target user"
	}

	return validation
}

func hasUnsupportedValue(values []string, allowed []string) bool {
	for _, value := range values {
		if !slices.Contains(allowed, value) {
			return true
		}
	}

	return false
}

func isValidRedirectURI(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}

	if parsed.Host == "" || parsed.Fragment != "" {
		return false
	}

	return true
}

func isAllowedRedirectURI(client *config.Client, redirectURI string) bool {
	if client == nil {
		return false
	}

	for _, allowed := range client.RedirectURIs {
		if redirectURI == allowed {
			return true
		}
	}

	return false
}

func isValidCodeChallenge(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}

	for _, r := range value {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '.' || r == '_' || r == '~':
		default:
			return false
		}
	}

	return true
}
