package web

import (
	"log/slog"
	"net/http"

	"github.com/infraconf/oidc-playground/public"
)

type OIDCHandler interface {
	Discovery(http.ResponseWriter, *http.Request)
	Authorize(http.ResponseWriter, *http.Request)
	Token(http.ResponseWriter, *http.Request)
	UserInfo(http.ResponseWriter, *http.Request)
	Revoke(http.ResponseWriter, *http.Request)
	JWKS(http.ResponseWriter, *http.Request)
}

func NewServer(addr string, logger *slog.Logger, handler OIDCHandler) (*http.Server, error) {
	mux := http.NewServeMux()

	assetFS, err := public.Assets()
	if err != nil {
		return nil, err
	}
	assetHandler := http.StripPrefix("/assets/", http.FileServer(assetFS))

	mux.Handle("GET /assets/", assetHandler)
	mux.HandleFunc("/.well-known/openid-configuration", handler.Discovery)
	mux.HandleFunc("/connect/authorize", handler.Authorize)
	mux.HandleFunc("/connect/token", handler.Token)
	mux.HandleFunc("/connect/userinfo", handler.UserInfo)
	mux.HandleFunc("/connect/revoke", handler.Revoke)
	mux.HandleFunc("/connect/jwks.json", handler.JWKS)

	return &http.Server{
		Addr:    addr,
		Handler: loggingMiddleware(logger, mux),
	}, nil
}

func loggingMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Info("request", "method", r.Method, "path", r.URL.Path, "remote_addr", r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}
