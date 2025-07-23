//go:build testdata
// +build testdata

/*
 * Go crypto vulnerabilities for key generation
 * Expected: HIGH severity findings for post-quantum migration
 * This file is excluded from normal builds and linting via build tags
 */
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
)

// Stub functions for test purposes
func storeKeys(privateKey *rsa.PrivateKey, ecdsaKey *ecdsa.PrivateKey) error {
	// Test stub
	return nil
}

func useSharedSecret(secret []byte) error {
	// Test stub
	return nil
}

// HIGH: RSA key generation for application use
func generateUserKeys() error {
	// HIGH severity: RSA key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// HIGH severity: ECDSA key generation
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	// MEDIUM severity: Ed25519 usage
	_, _, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	return storeKeys(privateKey, ecdsaKey)
}

// HIGH: ECDH key agreement
func performKeyExchange() error {
	curve := elliptic.P256()
	privateKey, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return err
	}

	// HIGH severity: ECDH operation
	sharedX, _ := curve.ScalarMult(x, y, privateKey)
	return useSharedSecret(sharedX.Bytes())
}

// HIGH: Weak hash usage in application
func hashUserPassword(password string) []byte {
	hasher := sha1.New() // HIGH: SHA-1 for passwords
	hasher.Write([]byte(password))
	return hasher.Sum(nil)
}

// CRITICAL: MD5 usage in application
func createSessionID(userID string) []byte {
	hasher := md5.New() // CRITICAL: MD5 for sessions
	hasher.Write([]byte(userID))
	return hasher.Sum(nil)
}

func main() {
	// Test main function
}
