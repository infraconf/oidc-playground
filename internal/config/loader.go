package config

import (
	"encoding/json"
	"fmt"
	"os"
)

const (
	DefaultPath = "/etc/idp/config.json"
	PathEnvVar  = "IDP_CONFIG_PATH"
)

func LoadFromEnv() (*Config, string, error) {
	path := os.Getenv(PathEnvVar)
	if path == "" {
		path = DefaultPath
	}

	cfg, err := Load(path)
	if err != nil {
		return nil, path, err
	}

	return cfg, path, nil
}

func Load(path string) (*Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(content, &cfg); err != nil {
		return nil, fmt.Errorf("decode config %q: %w", path, err)
	}

	if err := cfg.Server.ensureSigningKey(); err != nil {
		return nil, err
	}

	return &cfg, nil
}
