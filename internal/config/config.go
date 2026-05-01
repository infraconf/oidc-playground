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
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURIs []string `json:"redirect_uris"`
}

type StandardClaims struct {
	Email  string   `json:"email"`
	Groups []string `json:"groups"`
}

type ClaimSet map[string]any

type User struct {
	ID             string              `json:"id"`
	Name           string              `json:"name"`
	Description    string              `json:"description"`
	StandardClaims StandardClaims      `json:"claims"`
	CustomClaims   map[string]ClaimSet `json:"custom_claims"`
}

type Config struct {
	Server  Server   `json:"server"`
	Clients []Client `json:"clients"`
	Users   []User   `json:"users"`
}
