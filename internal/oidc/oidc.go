package oidc

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/infraconf/oidc-playground/internal/config"
)

type Handler struct {
	config   *config.Config
	mu       sync.Mutex
	codes    map[string]*Session
	sessions map[string]*Session
}

func NewHandler(cfg *config.Config) *Handler {
	return &Handler{
		config:   cfg,
		codes:    map[string]*Session{},
		sessions: map[string]*Session{},
	}
}

func (h *Handler) putCode(code string, session *Session) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.cleanupExpiredCodesLocked(time.Now())
	h.codes[code] = session
}

func (h *Handler) getCode(code string) (*Session, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.cleanupExpiredCodesLocked(time.Now())
	session, ok := h.codes[code]
	return session, ok
}

func (h *Handler) exchangeCode(code string) (*Session, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.cleanupExpiredCodesLocked(time.Now())

	session, ok := h.codes[code]
	if !ok {
		return nil, false
	}

	delete(h.codes, code)
	h.sessions[session.AccessToken] = session

	return session, true
}

func (h *Handler) getSession(accessToken string) (*Session, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	session, ok := h.sessions[accessToken]
	return session, ok
}

func (h *Handler) cleanupExpiredCodesLocked(now time.Time) {
	for code, session := range h.codes {
		if session.CodeExpireTime.Before(now) {
			delete(h.codes, code)
		}
	}
}

func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, r, "revoke")
}

func (h *Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []any{publicJWK(h.config.Server.SigningKey)},
	})
}

func (h *Handler) issuer(r *http.Request) string {
	if h.config.Server.Issuer != "" {
		return strings.TrimRight(h.config.Server.Issuer, "/")
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwardedProto := r.Header.Get("X-Forwarded-Proto"); forwardedProto != "" {
		scheme = forwardedProto
	}

	return scheme + "://" + r.Host
}

func (h *Handler) notImplemented(w http.ResponseWriter, r *http.Request, endpoint string) {
	writeJSON(w, http.StatusNotImplemented, map[string]any{
		"error":       "not_implemented",
		"description": "endpoint business logic not implemented yet",
		"endpoint":    endpoint,
		"method":      r.Method,
		"path":        r.URL.Path,
	})
}

func writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(payload); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func writeTokenError(w http.ResponseWriter, statusCode int, errorCode string, description string) {
	writeJSON(w, statusCode, map[string]any{
		"error":             errorCode,
		"error_description": description,
	})
}

func bigEndianBytes(value int) []byte {
	if value == 0 {
		return []byte{0}
	}

	var out []byte
	for value > 0 {
		out = append([]byte{byte(value & 0xff)}, out...)
		value >>= 8
	}

	return out
}
