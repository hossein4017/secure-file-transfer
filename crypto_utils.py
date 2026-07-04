#!/usr/bin/env python3
"""
Encryption Utilities - AES-256-GCM
"""

import os
import base64
import hashlib
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CHUNK_SIZE = 64 * 1024  # 64KB chunks


class SecureTransfer:
    """AES-256-GCM encryption/decryption with SHA-256 integrity verification"""

    def __init__(self, key_file="shared.key"):
        """Load key from file"""
        with open(key_file, 'r') as f:
            self.key = base64.b64decode(f.read().strip())

        if len(self.key) != 32:
            raise ValueError("Key must be exactly 32 bytes (256 bits)!")

        self.aesgcm = AESGCM(self.key)

    def get_file_hash(self, file_path):
        """Calculate SHA-256 hash of file"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(CHUNK_SIZE):
                sha256.update(chunk)
        return sha256.hexdigest()

    def encrypt_file(self, file_path):
        """
        Encrypt file with AES-256-GCM
        Returns: (encrypted_data, original_hash)
        """
        nonce = os.urandom(12)  # 96-bit random nonce
        original_hash = self.get_file_hash(file_path)

        with open(file_path, 'rb') as f:
            plaintext = f.read()

        # AES-256-GCM encryption (includes authentication tag)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, None)

        # Structure: nonce (12B) + ciphertext+tag
        encrypted_data = nonce + ciphertext

        return encrypted_data, original_hash

    def decrypt_file(self, encrypted_data, output_path, expected_hash=None):
        """
        Decrypt file and optionally verify hash
        """
        if len(encrypted_data) < 13:
            raise ValueError("Invalid encrypted data!")

        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        # Decrypt (verifies authentication tag automatically)
        plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)

        # Save decrypted file
        with open(output_path, 'wb') as f:
            f.write(plaintext)

        # Verify hash if provided
        if expected_hash:
            actual_hash = self.get_file_hash(output_path)
            if actual_hash != expected_hash:
                os.remove(output_path)  # Delete corrupted file
                raise ValueError(
                    f"Hash mismatch!\n"
                    f"Expected: {expected_hash}\n"
                    f"Actual:   {actual_hash}"
                )

        return output_path
