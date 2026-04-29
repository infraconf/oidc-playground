package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

func signIDToken(token IDToken, signingKey *rsa.PrivateKey) (string, error) {
	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": signingKeyID(signingKey),
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal jwt header: %w", err)
	}

	payloadJSON, err := json.Marshal(token)
	if err != nil {
		return "", fmt.Errorf("marshal jwt payload: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	digest := sha256.Sum256([]byte(signingInput))

	signature, err := signingKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func signingKeyID(signingKey *rsa.PrivateKey) string {
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&signingKey.PublicKey)
	if err != nil {
		return ""
	}
	keyIDHash := sha256.Sum256(publicKeyDER)

	return base64.RawURLEncoding.EncodeToString(keyIDHash[:])
}
