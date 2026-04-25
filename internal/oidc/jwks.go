package oidc

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
)

func publicJWK(privateKey *rsa.PrivateKey) map[string]any {
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return map[string]any{}
	}

	keyIDHash := sha256.Sum256(publicKeyDER)

	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": base64.RawURLEncoding.EncodeToString(keyIDHash[:]),
		"n":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(bigEndianBytes(privateKey.PublicKey.E)),
	}
}
