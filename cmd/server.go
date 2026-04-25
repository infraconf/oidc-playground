package main

import (
	"log/slog"
	"os"

	"github.com/infraconf/oidc-playground/internal/config"
	"github.com/infraconf/oidc-playground/internal/oidc"
	"github.com/infraconf/oidc-playground/internal/web"
)

func main() {
	logger := slog.New(
		slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}),
	)

	cfg, cfgPath, err := config.LoadFromEnv()
	if err != nil {
		logger.Error("load config", "path", cfgPath, "error", err)
		os.Exit(1)
	}

	handler := oidc.NewHandler(cfg)
	server := web.NewServer(":8080", logger.WithGroup("http"), handler)

	logger.Info("starting server", "addr", server.Addr, "config_path", cfgPath)
	if err := server.ListenAndServe(); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
