"""
AES-256-CBC Encryption/Decryption Module
Encrypts and decrypts files using user-provided passwords.
Key derivation via PBKDF2-HMAC-SHA256.
"""

import os
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Constants
SALT_SIZE = 16
IV_SIZE = 16
KEY_SIZE = 32  # 256 bits
ITERATIONS = 100_000
MAGIC_HEADER = b"ENCFILE1"  # 8-byte magic header to identify encrypted files


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(file_bytes: bytes, password: str) -> bytes:
    """
    Encrypt file bytes using AES-256-CBC.
    
    Output format:
    [MAGIC_HEADER (8 bytes)][SALT (16 bytes)][IV (16 bytes)][ENCRYPTED_DATA]
    
    Returns encrypted bytes.
    """
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)
    key = _derive_key(password, salt)

    # Pad the data to AES block size (16 bytes)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(file_bytes) + padder.finalize()

    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Pack: MAGIC + SALT + IV + ENCRYPTED_DATA
    return MAGIC_HEADER + salt + iv + encrypted_data


def decrypt_file(encrypted_bytes: bytes, password: str) -> bytes:
    """
    Decrypt AES-256-CBC encrypted file bytes.
    
    Expects format:
    [MAGIC_HEADER (8 bytes)][SALT (16 bytes)][IV (16 bytes)][ENCRYPTED_DATA]
    
    Returns original file bytes.
    Raises ValueError if password is wrong or data is corrupted.
    """
    # Validate magic header
    header_size = len(MAGIC_HEADER)
    if len(encrypted_bytes) < header_size + SALT_SIZE + IV_SIZE:
        raise ValueError("Invalid encrypted file: too small")

    magic = encrypted_bytes[:header_size]
    if magic != MAGIC_HEADER:
        raise ValueError("Invalid encrypted file: not an AES-encrypted file")

    # Extract salt, IV, and encrypted data
    offset = header_size
    salt = encrypted_bytes[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    iv = encrypted_bytes[offset : offset + IV_SIZE]
    offset += IV_SIZE
    encrypted_data = encrypted_bytes[offset:]

    # Derive key and decrypt
    key = _derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Unpad
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        original_data = unpadder.update(padded_data) + unpadder.finalize()
        return original_data
    except Exception:
        raise ValueError("Decryption failed: wrong password or corrupted file")


def is_encrypted_file(file_bytes: bytes) -> bool:
    """Check if file bytes start with our magic header."""
    return file_bytes[: len(MAGIC_HEADER)] == MAGIC_HEADER
