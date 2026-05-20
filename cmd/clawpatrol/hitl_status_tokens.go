package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func mintHITLOperationStatusToken() (string, string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", "", fmt.Errorf("mint hitl status token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	return token, hashHITLOperationStatusToken(token), nil
}

func hashHITLOperationStatusToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func verifyHITLOperationStatusTokenHash(token, expectedHash string) bool {
	if token == "" || expectedHash == "" {
		return false
	}
	candidateHash := hashHITLOperationStatusToken(token)
	return subtle.ConstantTimeCompare([]byte(candidateHash), []byte(expectedHash)) == 1
}
