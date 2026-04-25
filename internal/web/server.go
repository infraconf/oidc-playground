package web

import (
	"log/slog"
	"net/http"
)

type OIDCHandler interface {
	Discovery(http.ResponseWriter, *http.Request)
	Authorize(http.ResponseWriter, *http.Request)
	Token(http.ResponseWriter, *http.Request)
	UserInfo(http.ResponseWriter, *http.Request)
	Revoke(http.ResponseWriter, *http.Request)
	JWKS(http.ResponseWriter, *http.Request)
}

func NewServer(addr string, logger *slog.Logger, handler OIDCHandler) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", handler.Discovery)
	mux.HandleFunc("/connect/authorize", handler.Authorize)
	mux.HandleFunc("/connect/token", handler.Token)
	mux.HandleFunc("/connect/userinfo", handler.UserInfo)
	mux.HandleFunc("/connect/revoke", handler.Revoke)
	mux.HandleFunc("/connect/jwks.json", handler.JWKS)

	return &http.Server{
		Addr:    addr,
		Handler: loggingMiddleware(logger, mux),
	}
}

func loggingMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Info("request", "method", r.Method, "path", r.URL.Path, "remote_addr", r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}
