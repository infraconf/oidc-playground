package oidc

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"

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
