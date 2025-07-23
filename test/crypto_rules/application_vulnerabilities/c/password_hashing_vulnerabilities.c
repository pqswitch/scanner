/*
 * Application crypto vulnerabilities - THESE ARE REAL SECURITY ISSUES
 * Expected: HIGH/CRITICAL severity findings
 */
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

/* CRITICAL: Using MD5 for password hashing */
int hash_user_password(const char *password, char *hash_output) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_md5();  // CRITICAL: MD5 for passwords!
    
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, password, strlen(password));
    EVP_DigestFinal_ex(ctx, hash_output, NULL);
    
    EVP_MD_CTX_free(ctx);
    return 0;
}

/* HIGH: Using SHA-1 for session tokens */
int generate_session_token(const char *user_data, char *token) {
    // HIGH severity: SHA-1 for session tokens
    SHA1((unsigned char*)user_data, strlen(user_data), (unsigned char*)token);
    return 0;
}

/* CRITICAL: Using MD5 for authentication */
int authenticate_user(const char *username, const char *password) {
    char hash[16];
    // CRITICAL: MD5 for authentication
    MD5((unsigned char*)password, strlen(password), (unsigned char*)hash);
    return verify_hash(username, hash);
}

/* HIGH: Using SHA-1 for digital signatures */
int sign_document(const char *document, char *signature) {
    const EVP_MD *md = EVP_sha1();  // HIGH: SHA-1 for signatures
    // ... signature implementation
    return 0;
}

/* CRITICAL: Application-level crypto with weak algorithms */
int create_user_login_hash(const char *username, const char *password) {
    char combined[256];
    snprintf(combined, sizeof(combined), "%s:%s", username, password);
    
    // CRITICAL: Application using MD5 for login
    return hash_password_md5(combined);
} 