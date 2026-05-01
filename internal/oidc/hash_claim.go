package oidc

import (
	"crypto/sha256"
	"encoding/base64"
)

// OIDC c_hash/at_hash use the left-most half of the hash output for the token's signing algorithm.
// The server currently signs ID tokens with RS256, so SHA-256 is the correct digest here.
func hashClaim(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}
