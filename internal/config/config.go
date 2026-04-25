package config

import (
	"crypto/rsa"
)

type Server struct {
	Issuer           string          `json:"issuer"`
	SigningKeyBase64 string          `json:"signing_key"`
	SigningKey       *rsa.PrivateKey `json:"-"`
}

type Client struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type BaseClaims struct {
	Subject string   `json:"sub"`
	Email   string   `json:"email"`
	Groups  []string `json:"groups"`
}

type Claim map[string]any

type User struct {
	Name         string           `json:"name"`
	Description  string           `json:"description"`
	BaseClaims   BaseClaims       `json:"claims"`
	CustomClaims map[string]Claim `json:"custom_claims"`
}

type Config struct {
	Server  Server   `json:"server"`
	Clients []Client `json:"clients"`
	Users   []User   `json:"users"`
}
