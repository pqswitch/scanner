#!/usr/bin/env python3
"""
Test suite for crypto compatibility - should be INFO severity
Expected: INFO severity - "Legacy TLS version usage detected in test context"
Expected: INFO severity - "MD5 usage detected in test or non-cryptographic context"
"""

import hashlib
import unittest
from unittest.mock import patch
import ssl

class CryptoCompatibilityTest(unittest.TestCase):
    """Testing legacy crypto for backward compatibility"""
    
    def test_md5_compatibility(self):
        """Test MD5 compatibility with legacy systems"""
        # This is testing, not production usage - should be INFO
        md5_hash = hashlib.md5(b"test data").hexdigest()
        self.assertEqual(len(md5_hash), 32)
    
    def test_sha1_compatibility(self):
        """Test SHA-1 compatibility for git-like systems"""
        # Testing legacy SHA-1 support - should be INFO
        sha1_hash = hashlib.sha1(b"test data").hexdigest()
        self.assertEqual(len(sha1_hash), 40)
    
    def test_ssl_configuration(self):
        """Test SSL configuration options"""
        # Testing legacy SSL for compatibility - should be INFO
        ssl_config = {
            'protocol': 'SSLv3_method',
            'ciphers': 'ECDHE-RSA-AES128-SHA256'
        }
        self.assertIn('SSL', ssl_config['protocol'])
        
    def test_tls_cipher_suites(self):
        """Test various TLS cipher suites for compatibility"""
        # Testing cipher suites - should be INFO in test context
        test_ciphers = [
            'DHE-RSA-AES128-SHA256',
            'ECDHE-ECDSA-AES128-SHA256',
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
        ]
        for cipher in test_ciphers:
            self.assertIn('RSA', cipher or 'ECDHE' in cipher)

    def test_legacy_protocols(self):
        """Test legacy protocol support"""
        # Testing legacy protocols - should be INFO
        protocols = ['TLSv1_0', 'TLSv1_1', 'SSLv3']
        for protocol in protocols:
            self.assertTrue(protocol.startswith(('TLS', 'SSL')))

if __name__ == '__main__':
    unittest.main() 