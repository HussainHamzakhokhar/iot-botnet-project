"""
Security Configuration Module
=============================
Centralizes all security settings for the IoT Botnet Detection System.

Encryption Strategy:
- Data at Rest: AES-256-GCM for stored data (models, datasets, logs)
- Data in Transit: TLS 1.3 for all HTTP communications
- Key Management: PBKDF2 key derivation with secure key rotation
"""

import os
from dataclasses import dataclass
from typing import Optional
from pathlib import Path


@dataclass
class SecurityConfig:
    """
    Security configuration settings.
    
    Attributes:
        encryption_algorithm: Symmetric encryption algorithm (AES-256-GCM recommended)
        key_derivation_iterations: PBKDF2 iteration count (higher = more secure, slower)
        key_rotation_days: Days between automatic key rotations
        ssl_enabled: Enable HTTPS/TLS for API endpoints
        min_tls_version: Minimum TLS version (1.2 or 1.3)
        secure_headers_enabled: Enable security headers (CSP, HSTS, etc.)
    """
    
    # Encryption Settings
    encryption_algorithm: str = "AES-256-GCM"
    key_size_bits: int = 256
    iv_size_bytes: int = 12  # 96 bits for GCM mode
    tag_size_bytes: int = 16  # 128 bits authentication tag
    
    # Key Derivation Settings (PBKDF2)
    key_derivation_iterations: int = 600_000  # OWASP 2023 recommendation
    salt_size_bytes: int = 32
    
    # Key Rotation Policy
    key_rotation_days: int = 90
    max_key_age_days: int = 365
    
    # TLS/SSL Settings
    ssl_enabled: bool = True
    min_tls_version: str = "TLSv1.2"
    preferred_tls_version: str = "TLSv1.3"
    
    # Secure Headers
    secure_headers_enabled: bool = True
    hsts_max_age: int = 31536000  # 1 year in seconds
    
    # File Paths
    keys_directory: str = "keys"
    encrypted_data_directory: str = "encrypted_data"
    ssl_cert_path: str = "ssl/cert.pem"
    ssl_key_path: str = "ssl/key.pem"
    
    # Session Settings
    session_timeout_minutes: int = 30
    max_failed_attempts: int = 5
    lockout_duration_minutes: int = 15
    
    # API Security
    api_key_enabled: bool = True
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60
    
    @classmethod
    def from_environment(cls) -> "SecurityConfig":
        """
        Load security configuration from environment variables.
        Falls back to secure defaults if not specified.
        """
        return cls(
            encryption_algorithm=os.getenv("ENCRYPTION_ALGORITHM", "AES-256-GCM"),
            key_derivation_iterations=int(os.getenv("KEY_DERIVATION_ITERATIONS", "600000")),
            key_rotation_days=int(os.getenv("KEY_ROTATION_DAYS", "90")),
            ssl_enabled=os.getenv("SSL_ENABLED", "true").lower() == "true",
            min_tls_version=os.getenv("MIN_TLS_VERSION", "TLSv1.2"),
            keys_directory=os.getenv("KEYS_DIRECTORY", "keys"),
            ssl_cert_path=os.getenv("SSL_CERT_PATH", "ssl/cert.pem"),
            ssl_key_path=os.getenv("SSL_KEY_PATH", "ssl/key.pem"),
            api_key_enabled=os.getenv("API_KEY_ENABLED", "true").lower() == "true",
            rate_limit_requests=int(os.getenv("RATE_LIMIT_REQUESTS", "100")),
        )
    
    def ensure_directories(self) -> None:
        """Create necessary security directories if they don't exist."""
        Path(self.keys_directory).mkdir(parents=True, exist_ok=True)
        Path(self.encrypted_data_directory).mkdir(parents=True, exist_ok=True)
        Path(self.ssl_cert_path).parent.mkdir(parents=True, exist_ok=True)
    
    def validate(self) -> list[str]:
        """
        Validate security configuration.
        Returns list of warnings/errors.
        """
        issues = []
        
        if self.key_derivation_iterations < 100_000:
            issues.append("WARNING: Key derivation iterations below 100,000 is insecure")
        
        if not self.ssl_enabled:
            issues.append("WARNING: SSL/TLS is disabled - data in transit is not encrypted")
        
        if self.min_tls_version == "TLSv1.0" or self.min_tls_version == "TLSv1.1":
            issues.append("WARNING: TLS 1.0/1.1 are deprecated - use TLSv1.2 or higher")
        
        if self.key_rotation_days > 365:
            issues.append("WARNING: Key rotation period exceeds 1 year - consider more frequent rotation")
        
        if self.session_timeout_minutes > 60:
            issues.append("WARNING: Long session timeout increases security risk")
        
        return issues


# Global default configuration
DEFAULT_CONFIG = SecurityConfig()


def get_security_config() -> SecurityConfig:
    """Get security configuration from environment or defaults."""
    return SecurityConfig.from_environment()
