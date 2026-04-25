package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

func (s *Server) ensureSigningKey() error {
	if s.SigningKeyBase64 == "" {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("generate signing key: %w", err)
		}

		privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return fmt.Errorf("marshal generated signing key: %w", err)
		}

		s.SigningKey = privateKey
		s.SigningKeyBase64 = base64.StdEncoding.EncodeToString(privateKeyDER)
		return nil
	}

	privateKeyDER, err := base64.StdEncoding.DecodeString(s.SigningKeyBase64)
	if err != nil {
		return fmt.Errorf("decode server.signing_key as base64: %w", err)
	}

	privateKey, err := parseRSAPrivateKey(privateKeyDER)
	if err != nil {
		return fmt.Errorf("parse server.signing_key: %w", err)
	}

	s.SigningKey = privateKey
	return nil
}

func parseRSAPrivateKey(privateKeyDER []byte) (*rsa.PrivateKey, error) {
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyDER)
	if err == nil {
		return privateKey, nil
	}

	pkcs8Key, pkcs8Err := x509.ParsePKCS8PrivateKey(privateKeyDER)
	if pkcs8Err != nil {
		return nil, fmt.Errorf("expected RSA private key in PKCS#1 or PKCS#8 DER format: %w", pkcs8Err)
	}

	rsaKey, ok := pkcs8Key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected RSA private key in PKCS#8 DER format")
	}

	return rsaKey, nil
}
