/* 
 * Legitimate DNSSEC implementation as per RFC 4034/5155
 * Expected: INFO severity - "DNSSEC protocol SHA-1 support detected"
 * NOT: HIGH severity - "SHA-1 hash algorithm detected"
 */
#include <openssl/evp.h>

const EVP_MD* dnssec_algorithm_to_evp(int algorithm) {
    switch (algorithm) {
        case DNSSEC_ALGORITHM_RSASHA1:
                return EVP_sha1();  // Should be INFO: RFC compliant
        case DNSSEC_ALGORITHM_RSASHA1_NSEC3_SHA1:
                return EVP_sha1();  // Should be INFO: RFC compliant
        case DNSSEC_ALGORITHM_RSASHA256:
                return EVP_sha256();
        default:
                return NULL;
    }
}

const EVP_MD* dnssec_digest_to_evp(int digest) {
    switch (digest) {
        case DNSSEC_DIGEST_SHA1:
                return EVP_sha1();  // Should be INFO: RFC 4034 compliant
        case DNSSEC_DIGEST_SHA256:
                return EVP_sha256();
        default:
                return NULL;
    }
}

const EVP_MD* nsec3_algorithm_to_evp(int algorithm) {
    switch (algorithm) {
        case NSEC3_ALGORITHM_SHA1:
                return EVP_sha1();  // Should be INFO: RFC 5155 compliant
        default:
                return NULL;
    }
} 