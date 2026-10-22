import unittest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from services.encryption import EncryptionService
from services.audit import AuditService
from models import db, AuditLog
from app import app
from seed_data import seed_database

class TestNexaVaultCrypto(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config['TESTING'] = True
        with app.app_context():
            seed_database()

    def test_01_aes_gcm_envelope_encryption_roundtrip(self):
        """Test AES-256-GCM envelope encryption and decryption with SHA-256 integrity check."""
        enc = EncryptionService()
        sample_plaintext = b"Patient Sensitive Health Record: Hemoglobin 14.2 g/dL, HbA1c 5.4%."
        
        # Encrypt
        enc_result = enc.encrypt_file_data(sample_plaintext)
        self.assertIn('ciphertext', enc_result)
        self.assertIn('wrapped_dek_b64', enc_result)
        self.assertIn('sha256_hash', enc_result)

        # Decrypt
        decrypted = enc.decrypt_file_data(
            ciphertext=enc_result['ciphertext'],
            wrapped_dek_b64=enc_result['wrapped_dek_b64'],
            dek_nonce_b64=enc_result['dek_nonce_b64'],
            dek_tag_b64=enc_result['dek_tag_b64'],
            file_nonce_b64=enc_result['file_nonce_b64'],
            file_tag_b64=enc_result['file_tag_b64'],
            expected_sha256=enc_result['sha256_hash']
        )
        self.assertEqual(decrypted, sample_plaintext)

    def test_02_ciphertext_tampering_detection(self):
        """Verify that altering ciphertext causes AES-GCM tag verification failure."""
        enc = EncryptionService()
        sample_plaintext = b"Confidential clinical diagnostic pathology result."
        enc_result = enc.encrypt_file_data(sample_plaintext)

        # Tamper with 1 byte in ciphertext
        corrupted_ciphertext = bytearray(enc_result['ciphertext'])
        corrupted_ciphertext[0] ^= 0xFF

        with self.assertRaises(ValueError) as ctx:
            enc.decrypt_file_data(
                ciphertext=bytes(corrupted_ciphertext),
                wrapped_dek_b64=enc_result['wrapped_dek_b64'],
                dek_nonce_b64=enc_result['dek_nonce_b64'],
                dek_tag_b64=enc_result['dek_tag_b64'],
                file_nonce_b64=enc_result['file_nonce_b64'],
                file_tag_b64=enc_result['file_tag_b64'],
                expected_sha256=enc_result['sha256_hash']
            )
        self.assertIn("Cryptographic Decryption Error", str(ctx.exception))

    def test_03_audit_chain_verification_and_tamper_detection(self):
        """Verify audit hash chain passes initially, and detects unauthorized row alterations."""
        with app.app_context():
            # Initial verification must pass
            check = AuditService.verify_audit_chain()
            self.assertTrue(check['is_valid'])

            # Mutate row in database
            target_log = AuditLog.query.first()
            original_details = target_log.details
            target_log.details = original_details + " [MALICIOUS_INJECTION]"
            db.session.commit()

            # Verification must fail and pinpoint exact broken entry
            tamper_check = AuditService.verify_audit_chain()
            self.assertFalse(tamper_check['is_valid'])
            self.assertEqual(tamper_check['broken_at_id'], target_log.id)

            # Restore
            target_log.details = original_details
            db.session.commit()

if __name__ == '__main__':
    unittest.main()
