import os
from models import MedicalRecord, db
from services.encryption import EncryptionService
from services.threat_detection import ThreatDetectionService
from services.audit import AuditService

class IntegrityService:
    @classmethod
    def verify_record_integrity(cls, record: MedicalRecord, user=None, ip_address="127.0.0.1"):
        """
        Cryptographically verifies AES-GCM ciphertext integrity and SHA-256 plaintext baseline.
        """
        if not os.path.exists(record.encrypted_filepath):
            ThreatDetectionService.check_integrity_failure(
                record.record_id, record.original_filename,
                "Encrypted file missing from disk storage.",
                user=user, ip_address=ip_address
            )
            return {'is_valid': False, 'message': 'Encrypted file not found on physical storage.'}
            
        try:
            with open(record.encrypted_filepath, 'rb') as f:
                ciphertext = f.read()
                
            enc_service = EncryptionService()
            # Attempt unwrapping, GCM decryption, and SHA-256 verification
            decrypted_data = enc_service.decrypt_file_data(
                ciphertext=ciphertext,
                wrapped_dek_b64=record.wrapped_dek,
                dek_nonce_b64=record.dek_nonce,
                dek_tag_b64=record.dek_tag,
                file_nonce_b64=record.file_nonce,
                file_tag_b64=record.file_tag,
                expected_sha256=record.sha256_hash
            )
            
            return {
                'is_valid': True,
                'sha256': record.sha256_hash,
                'message': 'Cryptographic tag and SHA-256 digest match trusted baseline 100%.'
            }
            
        except Exception as e:
            ThreatDetectionService.check_integrity_failure(
                record.record_id, record.original_filename,
                str(e), user=user, ip_address=ip_address
            )
            return {
                'is_valid': False,
                'sha256': record.sha256_hash,
                'message': f"TAMPERING DETECTED: {str(e)}"
            }

    @classmethod
    def simulate_tampering_attack(cls, record_id_val: str):
        """
        FOR VIVA DEMONSTRATION: Intentionally alters ciphertext bytes on disk
        to prove that AES-GCM tag verification rejects corrupted data before decryption.
        """
        record = MedicalRecord.query.filter_by(record_id=record_id_val).first()
        if not record or not os.path.exists(record.encrypted_filepath):
            raise ValueError("Record or file not found.")
            
        with open(record.encrypted_filepath, 'r+b') as f:
            data = f.read()
            if len(data) > 10:
                # Corrupt the 5th byte
                f.seek(5)
                f.write(bytes([data[5] ^ 0xFF]))
                
        AuditService.log_event(
            event_type='VIVA_DEMO_TAMPER_SIMULATION',
            action=f"Simulated physical disk corruption on {record.record_id}",
            status='WARNING',
            target_resource=record.record_id,
            details="Bit-flip injected into ciphertext payload to demonstrate tamper detection."
        )
        return True
