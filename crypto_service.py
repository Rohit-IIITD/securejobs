"""
services/crypto_service.py — SecureJobs
=========================================
AES-256-GCM encryption/decryption for both files (resumes) and
messages.  Uses separate keys so a compromise of one doesn't affect
the other.
"""

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import AES_KEY, MESSAGE_KEY


# ── Resume / file encryption ──────────────────────────────────

def encrypt_file(data: bytes) -> bytes:
    """
    Encrypt raw file bytes with AES-256-GCM.
    Returns: nonce (12 bytes) || ciphertext.
    """
    aesgcm = AESGCM(AES_KEY)
    nonce  = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, data, None)


# ── Message encryption ────────────────────────────────────────

def encrypt_message(text: str) -> str:
    """
    Encrypt a plaintext message string.
    Returns base64-encoded nonce || ciphertext.
    """
    aes   = AESGCM(MESSAGE_KEY)
    nonce = os.urandom(12)
    ct    = aes.encrypt(nonce, text.encode(), None)
    return base64.b64encode(nonce + ct).decode()


def decrypt_message(ciphertext: str) -> str:
    """
    Decrypt a base64-encoded message produced by encrypt_message().
    Returns empty string for None/empty input (handles DB nulls safely).
    """
    if not ciphertext:
        return ""
    raw         = base64.b64decode(ciphertext)
    nonce, body = raw[:12], raw[12:]
    aes         = AESGCM(MESSAGE_KEY)
    return aes.decrypt(nonce, body, None).decode()
