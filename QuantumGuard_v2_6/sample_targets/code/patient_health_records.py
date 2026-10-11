"""
High-Confidentiality Patient Health Records Encryption Vault (HIPAA Compliant).
Vulnerable to Harvest Now, Decrypt Later (HNDL) due to long confidentiality retention (30 years).
"""
import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class PatientDataVault:
    def __init__(self):
        # Vulnerable RSA-2048 keypair generation (Shor polynomial-time break)
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        
    def encrypt_medical_record(self, record_payload: bytes) -> dict:
        # Generates ephemeral AES-128 key (Grover vulnerable: drops to 64-bit strength)
        session_key = os.urandom(16)
        iv = os.urandom(16)
        
        cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Pad payload to 16 bytes
        pad_len = 16 - (len(record_payload) % 16)
        padded_payload = record_payload + bytes([pad_len] * pad_len)
        ciphertext = encryptor.update(padded_payload) + encryptor.finalize()
        
        # Encrypt AES session key with RSA-2048 (VULNERABLE ASYMMETRIC KEY TRANSPORT)
        encrypted_session_key = self.public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Legacy integrity check with SHA-1
        integrity_hash = hashlib.sha1(record_payload).hexdigest()
        
        return {
            "encrypted_key": encrypted_session_key,
            "ciphertext": ciphertext,
            "iv": iv,
            "sha1_hash": integrity_hash
        }
