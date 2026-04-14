"""
services/pki_service.py — SecureJobs
======================================
RSA-based digital signatures for resume integrity and audit log rows.
Generates a self-signed RSA key pair on first use and stores it in memory.
"""
 
import base64
import logging
 
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
 
logger = logging.getLogger(__name__)
 
# ── Generate RSA key pair once at startup ─────────────────────
_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend(),
)
_public_key = _private_key.public_key()
 
 
def sign_resume(data: bytes) -> str:
    """Sign encrypted resume bytes. Returns base64-encoded signature."""
    signature = _private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode()
 
 
def verify_resume(data: bytes, signature_b64: str) -> bool:
    """Verify a resume signature. Returns True if valid."""
    try:
        sig = base64.b64decode(signature_b64)
        _public_key.verify(
            sig,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        logger.error("Resume verification error: %s", e)
        return False
 
 
def sign_audit_row(raw: str) -> str:
    """Sign an audit log row string. Returns base64-encoded signature."""
    signature = _private_key.sign(
        raw.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode()
 
 
def verify_audit_row(raw: str, signature_b64: str) -> bool:
    """Verify an audit row signature. Returns True if valid."""
    try:
        sig = base64.b64decode(signature_b64)
        _public_key.verify(
            sig,
            raw.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        logger.error("Audit row verification error: %s", e)
        return False
 
 
def get_public_key_pem() -> str:
    """Return the public key in PEM format for display in admin panel."""
    return _public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()