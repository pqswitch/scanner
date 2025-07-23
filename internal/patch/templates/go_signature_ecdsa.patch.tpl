--- {{.File}}
+++ {{.File}}
@@ -{{.Line}},6 +{{.Line}},6 @@
-	// ECDSA signature - vulnerable to quantum attacks
-	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
-	if err != nil {
-		return nil, err
-	}
+	// Post-quantum digital signature using ML-DSA
+	// TODO: Replace with liboqs-go implementation
+	// import "github.com/open-quantum-safe/liboqs-go/oqs"
+	
+	// For now, use stronger ECDSA curve as interim measure
+	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader) // Upgraded to P-384
+	if err != nil {
+		return nil, err
+	}
+	
+	// TODO: Add ML-DSA signature generation
+	// sigClient := oqs.Signature{}
+	// sigClient.Init("Dilithium3", nil)
+	// publicKey, secretKey, err := sigClient.Keypair()
+	// if err != nil {
+	//     return nil, err
+	// }
+	
+	// TODO: Implement hybrid signatures combining ECDSA and ML-DSA 