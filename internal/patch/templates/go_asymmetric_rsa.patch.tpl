--- {{.File}}
+++ {{.File}}
@@ -{{.Line}},7 +{{.Line}},7 @@
-	// RSA key generation - vulnerable to quantum attacks
-	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
-	if err != nil {
-		return nil, err
-	}
+	// Post-quantum key encapsulation using ML-KEM
+	// TODO: Replace with liboqs-go implementation
+	// import "github.com/open-quantum-safe/liboqs-go/oqs"
+	
+	// For now, use hybrid approach with larger RSA key
+	privateKey, err := rsa.GenerateKey(rand.Reader, 4096) // Increased key size
+	if err != nil {
+		return nil, err
+	}
+	
+	// TODO: Add ML-KEM key generation
+	// kemClient := oqs.KeyEncapsulation{}
+	// kemClient.Init("Kyber1024", nil)
+	// publicKey, secretKey, err := kemClient.Keypair()
+	// if err != nil {
+	//     return nil, err
+	// }
+	
+	// TODO: Implement hybrid encryption combining RSA and ML-KEM 