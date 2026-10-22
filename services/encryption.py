import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class EncryptionService:
    def __init__(self, master_key_path=None):
        if not master_key_path:
            from config import Config
            master_key_path = Config.MASTER_KEY_PATH
        
        self.master_key_path = master_key_path
        self.master_key = self._get_or_create_master_key()

    def _get_or_create_master_key(self) -> bytes:
        """
        Retrieves the 256-bit Master Key (KEK) from isolated instance storage,
        or generates a fresh cryptographically secure random key.
        """
        os.makedirs(os.path.dirname(self.master_key_path), exist_ok=True)
        if os.path.exists(self.master_key_path):
            with open(self.master_key_path, 'rb') as f:
                key_b64 = f.read().strip()
                return base64.b64decode(key_b64)
        else:
            # Generate 32 bytes (256-bit) high-entropy master key
            new_key = os.urandom(32)
            with open(self.master_key_path, 'wb') as f:
                f.write(base64.b64encode(new_key))
            return new_key

    def calculate_sha256(self, data: bytes) -> str:
        """Computes trusted SHA-256 digest of original plaintext data."""
        return hashlib.sha256(data).hexdigest()

    def encrypt_file_data(self, plaintext_bytes: bytes):
        """
        Two-tier envelope encryption:
        1. Generates ephemeral 256-bit Data Encryption Key (DEK).
        2. Computes plaintext SHA-256 checksum.
        3. Encrypts file bytes with DEK using AES-256-GCM (provides confidentiality + tag integrity).
        4. Wraps DEK with Application Master Key (KEK) using AES-256-GCM.
        """
        # Step 1: Plaintext hash
        sha256_hash = self.calculate_sha256(plaintext_bytes)
        
        # Step 2: Generate unique DEK
        dek = AESGCM.generate_key(bit_length=256)
        file_aesgcm = AESGCM(dek)
        
        # 12-byte standard nonce for AES-GCM
        file_nonce = os.urandom(12)
        # AESGCM.encrypt appends 16-byte authentication tag at the end of ciphertext
        encrypted_with_tag = file_aesgcm.encrypt(file_nonce, plaintext_bytes, None)
        ciphertext = encrypted_with_tag[:-16]
        file_tag = encrypted_with_tag[-16:]
        
        # Step 3: Wrap DEK using Master Key (KEK)
        master_aesgcm = AESGCM(self.master_key)
        dek_nonce = os.urandom(12)
        wrapped_dek_with_tag = master_aesgcm.encrypt(dek_nonce, dek, None)
        wrapped_dek = wrapped_dek_with_tag[:-16]
        dek_tag = wrapped_dek_with_tag[-16:]
        
        return {
            'sha256_hash': sha256_hash,
            'file_nonce_b64': base64.b64encode(file_nonce).decode('utf-8'),
            'file_tag_b64': base64.b64encode(file_tag).decode('utf-8'),
            'wrapped_dek_b64': base64.b64encode(wrapped_dek).decode('utf-8'),
            'dek_nonce_b64': base64.b64encode(dek_nonce).decode('utf-8'),
            'dek_tag_b64': base64.b64encode(dek_tag).decode('utf-8'),
            'ciphertext': ciphertext
        }

    def decrypt_file_data(self, ciphertext: bytes, wrapped_dek_b64: str,
                          dek_nonce_b64: str, dek_tag_b64: str,
                          file_nonce_b64: str, file_tag_b64: str,
                          expected_sha256: str) -> bytes:
        """
        Unwraps DEK and decrypts ciphertext with AES-256-GCM, verifying both
        GCM cryptographic tag and trusted SHA-256 integrity hash.
        Raises ValueError if tampering or corrupt key is detected.
        """
        try:
            # Step 1: Unwrap DEK
            master_aesgcm = AESGCM(self.master_key)
            dek_nonce = base64.b64decode(dek_nonce_b64)
            wrapped_dek = base64.b64decode(wrapped_dek_b64)
            dek_tag = base64.b64decode(dek_tag_b64)
            
            wrapped_full = wrapped_dek + dek_tag
            dek = master_aesgcm.decrypt(dek_nonce, wrapped_full, None)
            
            # Step 2: Decrypt file payload
            file_aesgcm = AESGCM(dek)
            file_nonce = base64.b64decode(file_nonce_b64)
            file_tag = base64.b64decode(file_tag_b64)
            
            ciphertext_full = ciphertext + file_tag
            decrypted_plaintext = file_aesgcm.decrypt(file_nonce, ciphertext_full, None)
            
            # Step 3: Verify trusted SHA-256 integrity digest
            calculated_sha256 = self.calculate_sha256(decrypted_plaintext)
            if calculated_sha256 != expected_sha256:
                raise ValueError(
                    f"CRITICAL FILE INTEGRITY VIOLATION: Computed hash {calculated_sha256} "
                    f"does not match trusted baseline hash {expected_sha256}"
                )
            
            return decrypted_plaintext
            
        except Exception as e:
            if "CRITICAL FILE INTEGRITY VIOLATION" in str(e):
                raise
            raise ValueError(f"Cryptographic Decryption Error: AES-GCM Tag verification failed or payload tampered. ({str(e)})")
