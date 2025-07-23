package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5" //nolint:gosec // Intentional weak crypto for demo purposes
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // Intentional weak crypto for demo purposes
	"fmt"
	"log"
)

// Example application with various cryptographic implementations
// This file is used to test the PQSwitch scanner

func main() {
	fmt.Println("Demo application with various crypto implementations")

	// Test RSA key generation (should be detected)
	testRSAKeyGeneration()

	// Test ECDSA key generation (should be detected)
	testECDSAKeyGeneration()

	// Test weak hash functions (should be detected)
	testWeakHashes()

	fmt.Println("Demo completed")
}

// RSA key generation - vulnerable to quantum attacks
func testRSAKeyGeneration() {
	fmt.Println("Generating RSA key...")

	// This should be detected by the scanner
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("RSA key generated with %d bits\n", privateKey.Size()*8)
}

// ECDSA key generation - vulnerable to quantum attacks
func testECDSAKeyGeneration() {
	fmt.Println("Generating ECDSA key...")

	// This should be detected by the scanner
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("ECDSA key generated with curve %s\n", privateKey.Curve.Params().Name)
}

// Weak hash functions - should be replaced
func testWeakHashes() {
	fmt.Println("Testing weak hash functions...")

	data := []byte("test data")

	// MD5 - cryptographically broken
	md5Hash := md5.Sum(data) //nolint:gosec // Intentional weak crypto for demo purposes
	fmt.Printf("MD5 hash: %x\n", md5Hash)

	// SHA-1 - deprecated
	sha1Hash := sha1.Sum(data) //nolint:gosec // Intentional weak crypto for demo purposes
	fmt.Printf("SHA-1 hash: %x\n", sha1Hash)
}

// Example of what the code should look like after migration
// Currently commented out as it requires liboqs library
/*
func postQuantumExample() {
	fmt.Println("Post-quantum cryptography example")

	// TODO: Replace with ML-KEM implementation
	// import "github.com/open-quantum-safe/liboqs-go/oqs"

	// kemClient := oqs.KeyEncapsulation{}
	// kemClient.Init("Kyber1024", nil)
	// publicKey, secretKey, err := kemClient.Keypair()
	// if err != nil {
	//     log.Fatal(err)
	// }

	// TODO: Replace with ML-DSA signatures
	// sigClient := oqs.Signature{}
	// sigClient.Init("Dilithium3", nil)
	// sigPublicKey, sigSecretKey, err := sigClient.Keypair()
	// if err != nil {
	//     log.Fatal(err)
	// }
}
*/
