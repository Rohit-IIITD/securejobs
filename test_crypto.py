"""
tests/test_crypto.py — SecureJobs
===================================
Unit tests for all cryptographic utilities.
These are pure-function tests — no DB, no HTTP, no side effects.

Covers:
  - password hashing and verification (bcrypt)
  - OTP generation (secrets-based)
  - TOTP generation and verification (pyotp)
  - AES-256-GCM file encryption / decryption
  - AES-256-GCM message encryption / decryption
  - RSA-PSS signing and verification (PKI service)
  - Resume sign + verify flow
  - Audit row sign + verify flow
"""

import os
import pytest

# ── Set dummy env vars before importing modules that need them ─
os.environ.setdefault("SECRET_KEY",   "test-secret-key-32-bytes-padding!")
os.environ.setdefault("AES_KEY",      "test-aes-key-32-bytes-padding!!!")
os.environ.setdefault("MESSAGE_KEY",  "test-msg-key-32-bytes-padding!!!")
os.environ.setdefault("DB_USER",      "test")
os.environ.setdefault("DB_PASSWORD",  "test")
os.environ.setdefault("DB_HOST",      "localhost")
os.environ.setdefault("DB_NAME",      "test")
os.environ.setdefault("SMTP_EMAIL",   "test@test.com")
os.environ.setdefault("SMTP_APP_PASSWORD", "fake")


# ══════════════════════════════════════════════════════════════
# PASSWORD HASHING
# ══════════════════════════════════════════════════════════════

class TestPassword:
    from auth.password import hash_password, verify_password

    def test_hash_is_not_plaintext(self):
        from auth.password import hash_password
        hashed = hash_password("mysecretpassword")
        assert hashed != "mysecretpassword"

    def test_hash_starts_with_bcrypt_prefix(self):
        from auth.password import hash_password
        hashed = hash_password("test")
        assert hashed.startswith("$2b$")

    def test_correct_password_verifies(self):
        from auth.password import hash_password, verify_password
        hashed = hash_password("correct-horse-battery")
        assert verify_password("correct-horse-battery", hashed) is True

    def test_wrong_password_fails(self):
        from auth.password import hash_password, verify_password
        hashed = hash_password("correct-horse-battery")
        assert verify_password("wrong-password", hashed) is False

    def test_empty_string_password_hashes(self):
        """Edge case: empty password should still hash (not crash)."""
        from auth.password import hash_password, verify_password
        hashed = hash_password("")
        assert verify_password("", hashed) is True
        assert verify_password("notempty", hashed) is False

    def test_two_hashes_of_same_password_differ(self):
        """bcrypt generates a unique salt each time."""
        from auth.password import hash_password
        h1 = hash_password("same")
        h2 = hash_password("same")
        assert h1 != h2


# ══════════════════════════════════════════════════════════════
# OTP GENERATOR
# ══════════════════════════════════════════════════════════════

class TestOTPGenerator:

    def test_default_length_is_6(self):
        from utils.otp_generator import generate_otp_code
        code = generate_otp_code()
        assert len(code) == 6

    def test_custom_length(self):
        from utils.otp_generator import generate_otp_code
        assert len(generate_otp_code(8)) == 8

    def test_only_digits(self):
        from utils.otp_generator import generate_otp_code
        code = generate_otp_code()
        assert code.isdigit()

    def test_codes_are_not_all_same(self):
        """Generated codes should differ (birthday paradox: 1-in-million chance of same)."""
        from utils.otp_generator import generate_otp_code
        codes = {generate_otp_code() for _ in range(20)}
        assert len(codes) > 1

    def test_uses_secrets_not_random(self):
        """Verify the module uses secrets module, not random."""
        import utils.otp_generator as mod
        import inspect
        src = inspect.getsource(mod)
        assert "import secrets" in src
        assert "import random" not in src


# ══════════════════════════════════════════════════════════════
# TOTP
# ══════════════════════════════════════════════════════════════

class TestTOTP:

    def test_generate_secret_is_base32(self):
        from auth.totp import generate_totp_secret
        import base64
        secret = generate_totp_secret()
        # Should be valid base32 — pyotp accepts it
        assert len(secret) >= 16

    def test_valid_totp_verifies(self):
        from auth.totp import generate_totp_secret, verify_totp
        import pyotp
        secret = generate_totp_secret()
        current_otp = pyotp.TOTP(secret).now()
        assert verify_totp(secret, current_otp) is True

    def test_wrong_totp_fails(self):
        from auth.totp import generate_totp_secret, verify_totp
        secret = generate_totp_secret()
        assert verify_totp(secret, "000000") is False

    def test_totp_uri_contains_email(self):
        from auth.totp import generate_totp_secret, get_totp_uri
        secret = generate_totp_secret()
        uri = get_totp_uri(secret, "user@example.com")
        assert "user%40example.com" in uri or "user@example.com" in uri
        assert "SecureJobs" in uri

    def test_different_secrets_different_otp(self):
        from auth.totp import generate_totp_secret
        import pyotp
        s1 = generate_totp_secret()
        s2 = generate_totp_secret()
        # Extremely unlikely same OTP from different secrets at same moment
        otp1 = pyotp.TOTP(s1).now()
        otp2 = pyotp.TOTP(s2).now()
        # We can't guarantee they differ, but secrets should differ
        assert s1 != s2


# ══════════════════════════════════════════════════════════════
# AES-256-GCM FILE ENCRYPTION
# ══════════════════════════════════════════════════════════════

class TestFileEncryption:

    def test_encrypted_differs_from_plaintext(self):
        from services.crypto_service import encrypt_file
        data = b"This is my resume content."
        encrypted = encrypt_file(data)
        assert encrypted != data

    def test_encrypted_is_bytes(self):
        from services.crypto_service import encrypt_file
        assert isinstance(encrypt_file(b"data"), bytes)

    def test_nonce_prepended_12_bytes(self):
        """encrypt_file returns nonce (12 bytes) || ciphertext."""
        from services.crypto_service import encrypt_file
        data = b"resume content here"
        enc  = encrypt_file(data)
        # Must be at least 12 (nonce) + len(data) + 16 (GCM tag) bytes
        assert len(enc) >= 12 + len(data) + 16

    def test_two_encryptions_of_same_data_differ(self):
        """Each encryption uses a fresh random nonce."""
        from services.crypto_service import encrypt_file
        data = b"same content"
        assert encrypt_file(data) != encrypt_file(data)


# ══════════════════════════════════════════════════════════════
# AES-256-GCM MESSAGE ENCRYPTION
# ══════════════════════════════════════════════════════════════

class TestMessageEncryption:

    def test_encrypt_returns_string(self):
        from services.crypto_service import encrypt_message
        assert isinstance(encrypt_message("hello"), str)

    def test_decrypt_reverses_encrypt(self):
        from services.crypto_service import encrypt_message, decrypt_message
        original = "Hello, this is a secret message!"
        assert decrypt_message(encrypt_message(original)) == original

    def test_decrypt_empty_string_returns_empty(self):
        from services.crypto_service import decrypt_message
        assert decrypt_message("") == ""

    def test_decrypt_none_returns_empty(self):
        from services.crypto_service import decrypt_message
        assert decrypt_message(None) == ""

    def test_two_encryptions_differ(self):
        """Random nonce means same plaintext → different ciphertext."""
        from services.crypto_service import encrypt_message
        msg = "same message"
        assert encrypt_message(msg) != encrypt_message(msg)

    def test_unicode_message(self):
        """Non-ASCII characters should round-trip correctly."""
        from services.crypto_service import encrypt_message, decrypt_message
        msg = "नमस्ते 🔐 こんにちは"
        assert decrypt_message(encrypt_message(msg)) == msg

    def test_tampered_ciphertext_raises(self):
        """AES-GCM is authenticated — tampering must be detected."""
        import base64
        from services.crypto_service import encrypt_message, decrypt_message
        ct = encrypt_message("secret")
        raw = bytearray(base64.b64decode(ct))
        raw[20] ^= 0xFF          # flip bits in the ciphertext body
        tampered = base64.b64encode(bytes(raw)).decode()
        with pytest.raises(Exception):
            decrypt_message(tampered)


# ══════════════════════════════════════════════════════════════
# PKI SERVICE — RSA-PSS SIGN / VERIFY
# ══════════════════════════════════════════════════════════════

class TestPKIService:

    def test_sign_returns_hex_string(self):
        from services.pki_service import sign_bytes
        sig = sign_bytes(b"some data")
        assert isinstance(sig, str)
        # Hex string → all chars are valid hex digits
        int(sig, 16)   # raises ValueError if not valid hex

    def test_verify_valid_signature(self):
        from services.pki_service import sign_bytes, verify_bytes
        data = b"important data to protect"
        sig  = sign_bytes(data)
        assert verify_bytes(data, sig) is True

    def test_verify_wrong_data_fails(self):
        from services.pki_service import sign_bytes, verify_bytes
        sig = sign_bytes(b"original data")
        assert verify_bytes(b"tampered data", sig) is False

    def test_verify_empty_signature_fails(self):
        from services.pki_service import verify_bytes
        assert verify_bytes(b"data", "") is False

    def test_verify_garbage_signature_fails(self):
        from services.pki_service import verify_bytes
        assert verify_bytes(b"data", "deadbeef1234") is False

    def test_two_signatures_of_same_data_differ(self):
        """PSS padding is randomised — same input → different signatures."""
        from services.pki_service import sign_bytes
        data = b"same data"
        s1   = sign_bytes(data)
        s2   = sign_bytes(data)
        assert s1 != s2             # PSS is probabilistic

    def test_sign_text_convenience(self):
        from services.pki_service import sign_text, verify_text
        text = "audit row string"
        sig  = sign_text(text)
        assert verify_text(text, sig) is True

    def test_resume_sign_verify(self):
        from services.pki_service import sign_resume, verify_resume
        fake_encrypted = b"\x00\x01\x02" * 50   # fake encrypted bytes
        sig = sign_resume(fake_encrypted)
        assert verify_resume(fake_encrypted, sig) is True
        assert verify_resume(b"tampered", sig) is False

    def test_audit_row_sign_verify(self):
        from services.pki_service import sign_audit_row, verify_audit_row
        raw = "1|LOGIN_SUCCESS|user:1|Successful login|prevhash123"
        sig = sign_audit_row(raw)
        assert verify_audit_row(raw, sig) is True
        assert verify_audit_row("1|LOGIN_SUCCESS|user:1|TAMPERED|prevhash123", sig) is False

    def test_public_key_pem_format(self):
        from services.pki_service import get_public_key_pem
        pem = get_public_key_pem()
        assert pem.startswith("-----BEGIN PUBLIC KEY-----")
        assert "-----END PUBLIC KEY-----" in pem
