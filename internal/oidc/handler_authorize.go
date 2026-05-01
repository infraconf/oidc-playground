package oidc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/infraconf/oidc-playground/internal/config"
	"github.com/infraconf/oidc-playground/pkg/gen"
	"github.com/infraconf/oidc-playground/public"
)

func findClient(clients []config.Client, clientID string) *config.Client {
	for i := range clients {
		if clients[i].ClientID == clientID {
			return &clients[i]
		}
	}

	return nil
}

func findUser(users []config.User, userID string) *config.User {
	for i := range users {
		if users[i].ID == userID {
			return &users[i]
		}
	}

	return nil
}

func parseAuthorizeParams(r *http.Request) *AuthorizeParams {
	return &AuthorizeParams{
		ResponseType:        strings.TrimSpace(r.Form.Get("response_type")),
		ClientID:            strings.TrimSpace(r.Form.Get("client_id")),
		RedirectURI:         strings.TrimSpace(r.Form.Get("redirect_uri")),
		Scope:               normalizeScopes(r.Form.Get("scope")),
		State:               strings.TrimSpace(r.Form.Get("state")),
		Nonce:               strings.TrimSpace(r.Form.Get("nonce")),
		CodeChallenge:       strings.TrimSpace(r.Form.Get("code_challenge")),
		CodeChallengeMethod: strings.TrimSpace(r.Form.Get("code_challenge_method")),
		TargetUser:          strings.TrimSpace(r.Form.Get("target_user")),
		Options:             splitParameterList(r.Form.Get("options")),
	}
}

func splitParameterList(value string) []string {
	if value == "" {
		return nil
	}

	return strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})
}

func (h *Handler) authorizeSettings(w http.ResponseWriter, params *AuthorizeParams, validation authorizeValidation) {
	paramList := []AuthorizationRequestParameter{
		{"Response Type", params.ResponseType, params.ResponseType == "code"},
		{"Client ID", params.ClientID, findClient(h.config.Clients, params.ClientID) != nil},
		{"Redirect URI", params.RedirectURI, isValidRedirectURI(params.RedirectURI) && isAllowedRedirectURI(validation.client, params.RedirectURI)},
		{"Scope", params.Scope, len(validation.scopes) > 0 && slices.Contains(validation.scopes, "openid")},
		{"State", params.State, params.State != ""},
		{"Nonce", params.Nonce, params.Nonce != ""},
		{"Code Challenge", params.CodeChallenge, params.CodeChallenge != "" && isValidCodeChallenge(params.CodeChallenge)},
		{"Code Challenge Method", params.CodeChallengeMethod, params.CodeChallengeMethod == "S256"},
	}

	dataStruct := &AuthorizationPageModel{
		Users:        h.config.Users,
		Params:       *params,
		ErrorMessage: validation.errorMessage,
	}

	details, err := json.Marshal(dataStruct)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	data := AuthorizationPageData{
		Params:                 paramList,
		Users:                  h.config.Users,
		AuthorizationPageModel: string(details),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := public.RenderAuthorize(w, data); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func buildUserInfo(user config.User, scopes []string, token IDToken) *IDToken {
	userInfo := token

	if slices.Contains(scopes, "profile") {
		userInfo.PreferredUsername = user.ID
		userInfo.Name = user.Name
		userInfo.GivenName = user.Name
		userInfo.Nickname = user.ID
	}

	if slices.Contains(scopes, "groups") {
		groups := append([]string(nil), user.StandardClaims.Groups...)
		userInfo.Groups = &groups
	}

	if slices.Contains(scopes, "email") {
		ev := true
		userInfo.Email = user.StandardClaims.Email
		userInfo.EmailVerified = &ev
	}

	if user.CustomClaims != nil {
		userInfo.Extras = map[string]any{}
		for _, scope := range scopes {
			claims, ok := user.CustomClaims[scope]
			if !ok {
				continue
			}
			for key, value := range claims {
				userInfo.Extras[key] = value
			}
		}
		if len(userInfo.Extras) == 0 {
			userInfo.Extras = nil
		}
	}

	return &userInfo
}

func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":       "invalid_request",
			"description": "failed to parse authorize parameters",
		})
		return
	}

	params := parseAuthorizeParams(r)
	validation := validateAuthorizeParams(h.config, params)

	if params.TargetUser == "" {
		h.authorizeSettings(w, params, validation)
		return
	}

	if validation.errorMessage != "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":       "invalid_request",
			"description": validation.errorMessage,
		})
		return
	}

	code, _ := gen.Hex(16)
	accessToken, _ := gen.Hex(128)
	now := time.Now()
	sessionExpireTime := now.Add(60 * time.Minute)
	session := &Session{
		AccessToken:         accessToken,
		ClientID:            params.ClientID,
		RedirectURI:         params.RedirectURI,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
		CodeExpireTime:      now.Add(10 * time.Second),
		SessionExpireTime:   sessionExpireTime,
	}

	if slices.Contains(validation.scopes, "openid") {
		iat := int(now.Unix())
		exp := int(sessionExpireTime.Unix())

		idToken := IDToken{
			Issuer:         h.issuer(r),
			Subject:        subjectFromUserID(validation.targetUser.ID),
			Audience:       params.ClientID,
			ExpirationTime: exp,
			IssuedAt:       iat,
			AuthTime:       iat,
			Nonce:          params.Nonce,
		}

		userInfo := buildUserInfo(*validation.targetUser, validation.scopes, idToken)

		if slices.Contains(validation.options, "full-id-token") {
			idToken = *userInfo
		}

		idToken.CodeHash = hashClaim(code)
		idToken.AccessTokenHash = hashClaim(accessToken)

		idTokenJWT, err := signIDToken(idToken, h.config.Server.SigningKey)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error":       "server_error",
				"description": "failed to sign id token",
			})
			return
		}

		userInfoJSON, err := json.Marshal(userInfo)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error":       "server_error",
				"description": "failed to serialize user info",
			})
			return
		}

		session.IDToken = idTokenJWT
		session.UserInfo = userInfoJSON
	}

	h.putCode(code, session)

	redirectURL, err := buildAuthorizationRedirect(params.RedirectURI, code, params.State)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error":       "server_error",
			"description": "failed to build redirect uri",
		})
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

func buildAuthorizationRedirect(rawRedirectURI string, code string, state string) (string, error) {
	redirectURI, err := url.Parse(rawRedirectURI)
	if err != nil {
		return "", fmt.Errorf("parse redirect uri: %w", err)
	}

	query := redirectURI.Query()
	query.Set("code", code)
	if state != "" {
		query.Set("state", state)
	}
	redirectURI.RawQuery = query.Encode()

	return redirectURI.String(), nil
}

func subjectFromUserID(userID string) string {
	sum := sha256.Sum256([]byte(userID))
	return hex.EncodeToString(sum[:])
}
