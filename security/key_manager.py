"""
Key Management Module
=====================
Secure key generation, storage, rotation, and recovery for the IoT Botnet Detection System.

Security Features:
- Cryptographically secure key generation using os.urandom()
- PBKDF2 key derivation for password-based keys
- Automatic key rotation with configurable policy
- Encrypted key storage with master key protection
- Key versioning for seamless rotation
"""

import os
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass, asdict
from base64 import b64encode, b64decode

# Use cryptography library for secure operations
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("WARNING: 'cryptography' library not installed. Run: pip install cryptography")

from .config import SecurityConfig, get_security_config


@dataclass
class KeyMetadata:
    """Metadata for a cryptographic key."""
    key_id: str
    algorithm: str
    created_at: str
    expires_at: str
    version: int
    purpose: str  # 'data', 'model', 'api', 'session'
    is_active: bool = True
    rotated_from: Optional[str] = None


class KeyManager:
    """
    Manages cryptographic keys for the IoT Botnet Detection System.
    
    Responsibilities:
    - Generate cryptographically secure keys
    - Derive keys from passwords using PBKDF2
    - Store keys securely with encryption
    - Rotate keys based on policy
    - Provide key recovery mechanisms
    """
    
    def __init__(self, config: Optional[SecurityConfig] = None):
        self.config = config or get_security_config()
        self.keys_dir = Path(self.config.keys_directory)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self._master_key: Optional[bytes] = None
        self._keys_cache: Dict[str, bytes] = {}
        
    def generate_key(self, purpose: str = "data", key_size_bits: int = 256) -> Tuple[str, bytes]:
        """
        Generate a new cryptographically secure key.
        
        Args:
            purpose: Key purpose ('data', 'model', 'api', 'session')
            key_size_bits: Key size in bits (128, 192, or 256)
            
        Returns:
            Tuple of (key_id, key_bytes)
        """
        key_size_bytes = key_size_bits // 8
        key = os.urandom(key_size_bytes)
        key_id = self._generate_key_id(purpose)
        
        # Store key with metadata
        metadata = KeyMetadata(
            key_id=key_id,
            algorithm=self.config.encryption_algorithm,
            created_at=datetime.utcnow().isoformat(),
            expires_at=(datetime.utcnow() + timedelta(days=self.config.key_rotation_days)).isoformat(),
            version=1,
            purpose=purpose,
            is_active=True
        )
        
        self._store_key(key_id, key, metadata)
        self._keys_cache[key_id] = key
        
        return key_id, key
    
    def derive_key_from_password(
        self, 
        password: str, 
        salt: Optional[bytes] = None,
        purpose: str = "data"
    ) -> Tuple[bytes, bytes]:
        """
        Derive a cryptographic key from a password using PBKDF2.
        
        Args:
            password: User password or passphrase
            salt: Optional salt (generated if not provided)
            purpose: Key purpose for metadata
            
        Returns:
            Tuple of (derived_key, salt)
        """
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library required for key derivation")
        
        if salt is None:
            salt = os.urandom(self.config.salt_size_bytes)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.config.key_size_bits // 8,
            salt=salt,
            iterations=self.config.key_derivation_iterations,
            backend=default_backend()
        )
        
        key = kdf.derive(password.encode('utf-8'))
        return key, salt
    
    def get_key(self, key_id: str) -> Optional[bytes]:
        """
        Retrieve a key by ID.
        
        Args:
            key_id: The key identifier
            
        Returns:
            Key bytes or None if not found
        """
        # Check cache first
        if key_id in self._keys_cache:
            return self._keys_cache[key_id]
        
        # Load from storage
        key_path = self.keys_dir / f"{key_id}.key"
        if not key_path.exists():
            return None
        
        key = self._load_key(key_id)
        if key:
            self._keys_cache[key_id] = key
        
        return key
    
    def get_active_key(self, purpose: str = "data") -> Tuple[Optional[str], Optional[bytes]]:
        """
        Get the currently active key for a specific purpose.
        
        Args:
            purpose: Key purpose ('data', 'model', 'api', 'session')
            
        Returns:
            Tuple of (key_id, key_bytes) or (None, None)
        """
        metadata_path = self.keys_dir / "metadata.json"
        if not metadata_path.exists():
            return None, None
        
        with open(metadata_path, 'r') as f:
            all_metadata = json.load(f)
        
        # Find active key for purpose
        for key_id, meta in all_metadata.items():
            if meta.get('purpose') == purpose and meta.get('is_active', False):
                key = self.get_key(key_id)
                if key:
                    return key_id, key
        
        return None, None
    
    def rotate_key(self, old_key_id: str) -> Tuple[str, bytes]:
        """
        Rotate a key - generate new key and mark old as inactive.
        
        Args:
            old_key_id: ID of key to rotate
            
        Returns:
            Tuple of (new_key_id, new_key_bytes)
        """
        # Load old key metadata
        metadata = self._load_metadata(old_key_id)
        if not metadata:
            raise ValueError(f"Key {old_key_id} not found")
        
        # Generate new key
        new_key_id, new_key = self.generate_key(
            purpose=metadata.get('purpose', 'data'),
            key_size_bits=self.config.key_size_bits
        )
        
        # Update new key metadata with rotation info
        new_metadata = self._load_metadata(new_key_id)
        new_metadata['rotated_from'] = old_key_id
        new_metadata['version'] = metadata.get('version', 1) + 1
        self._save_metadata(new_key_id, new_metadata)
        
        # Mark old key as inactive
        metadata['is_active'] = False
        self._save_metadata(old_key_id, metadata)
        
        return new_key_id, new_key
    
    def check_key_expiration(self) -> list[str]:
        """
        Check for keys that need rotation.
        
        Returns:
            List of key IDs that need rotation
        """
        needs_rotation = []
        metadata_path = self.keys_dir / "metadata.json"
        
        if not metadata_path.exists():
            return needs_rotation
        
        with open(metadata_path, 'r') as f:
            all_metadata = json.load(f)
        
        now = datetime.utcnow()
        for key_id, meta in all_metadata.items():
            if not meta.get('is_active', False):
                continue
            
            expires_at = datetime.fromisoformat(meta.get('expires_at', now.isoformat()))
            if expires_at <= now:
                needs_rotation.append(key_id)
        
        return needs_rotation
    
    def generate_api_key(self) -> str:
        """
        Generate a secure API key for authentication.
        
        Returns:
            API key string (URL-safe base64)
        """
        return secrets.token_urlsafe(32)
    
    def hash_api_key(self, api_key: str) -> str:
        """
        Create a secure hash of an API key for storage.
        
        Args:
            api_key: The API key to hash
            
        Returns:
            SHA-256 hash of the API key
        """
        return hashlib.sha256(api_key.encode()).hexdigest()
    
    def initialize_master_key(self, password: Optional[str] = None) -> None:
        """
        Initialize or load the master key for encrypting other keys.
        
        Args:
            password: Optional password for master key derivation
        """
        master_key_path = self.keys_dir / ".master"
        
        if master_key_path.exists():
            # Load existing master key (in production, this would be from HSM or KMS)
            with open(master_key_path, 'rb') as f:
                self._master_key = f.read()
        elif password:
            # Derive master key from password
            salt_path = self.keys_dir / ".master_salt"
            if salt_path.exists():
                with open(salt_path, 'rb') as f:
                    salt = f.read()
            else:
                salt = os.urandom(32)
                with open(salt_path, 'wb') as f:
                    f.write(salt)
                os.chmod(salt_path, 0o600)
            
            self._master_key, _ = self.derive_key_from_password(password, salt)
            
            # Store encrypted master key indicator
            with open(master_key_path, 'wb') as f:
                f.write(self._master_key)
            os.chmod(master_key_path, 0o600)
        else:
            # Generate new master key
            self._master_key = os.urandom(32)
            with open(master_key_path, 'wb') as f:
                f.write(self._master_key)
            os.chmod(master_key_path, 0o600)
    
    def export_key_backup(self, key_id: str, backup_password: str) -> bytes:
        """
        Export a key for backup (encrypted with password).
        
        Args:
            key_id: Key to export
            backup_password: Password to encrypt backup
            
        Returns:
            Encrypted key backup bytes
        """
        key = self.get_key(key_id)
        if not key:
            raise ValueError(f"Key {key_id} not found")
        
        # Derive encryption key from password
        backup_key, salt = self.derive_key_from_password(backup_password)
        
        if CRYPTO_AVAILABLE:
            # Use Fernet for backup encryption
            fernet_key = b64encode(backup_key)
            f = Fernet(fernet_key)
            encrypted = f.encrypt(key)
            
            # Include salt in backup
            return salt + encrypted
        else:
            raise RuntimeError("cryptography library required for key backup")
    
    def import_key_backup(self, backup_data: bytes, backup_password: str, purpose: str = "data") -> str:
        """
        Import a key from backup.
        
        Args:
            backup_data: Encrypted backup bytes
            backup_password: Password to decrypt backup
            purpose: Purpose for the imported key
            
        Returns:
            Key ID of imported key
        """
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library required for key import")
        
        # Extract salt and encrypted data
        salt = backup_data[:self.config.salt_size_bytes]
        encrypted = backup_data[self.config.salt_size_bytes:]
        
        # Derive decryption key
        backup_key, _ = self.derive_key_from_password(backup_password, salt)
        
        # Decrypt
        fernet_key = b64encode(backup_key)
        f = Fernet(fernet_key)
        key = f.decrypt(encrypted)
        
        # Store imported key
        key_id = self._generate_key_id(purpose)
        metadata = KeyMetadata(
            key_id=key_id,
            algorithm=self.config.encryption_algorithm,
            created_at=datetime.utcnow().isoformat(),
            expires_at=(datetime.utcnow() + timedelta(days=self.config.key_rotation_days)).isoformat(),
            version=1,
            purpose=purpose,
            is_active=True
        )
        
        self._store_key(key_id, key, metadata)
        return key_id
    
    def _generate_key_id(self, purpose: str) -> str:
        """Generate a unique key ID."""
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        random_part = secrets.token_hex(4)
        return f"{purpose}_{timestamp}_{random_part}"
    
    def _store_key(self, key_id: str, key: bytes, metadata: KeyMetadata) -> None:
        """Store a key and its metadata securely."""
        # Store key (in production, use HSM or encrypted storage)
        key_path = self.keys_dir / f"{key_id}.key"
        
        if self._master_key and CRYPTO_AVAILABLE:
            # Encrypt key with master key
            fernet_key = b64encode(self._master_key)
            f = Fernet(fernet_key)
            encrypted_key = f.encrypt(key)
            with open(key_path, 'wb') as file:
                file.write(encrypted_key)
        else:
            # Store unencrypted (development only)
            with open(key_path, 'wb') as file:
                file.write(key)
        
        os.chmod(key_path, 0o600)  # Restrict permissions
        
        # Store metadata
        self._save_metadata(key_id, asdict(metadata))
    
    def _load_key(self, key_id: str) -> Optional[bytes]:
        """Load a key from storage."""
        key_path = self.keys_dir / f"{key_id}.key"
        if not key_path.exists():
            return None
        
        with open(key_path, 'rb') as f:
            data = f.read()
        
        if self._master_key and CRYPTO_AVAILABLE:
            # Decrypt key with master key
            fernet_key = b64encode(self._master_key)
            f = Fernet(fernet_key)
            return f.decrypt(data)
        
        return data
    
    def _load_metadata(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Load metadata for a key."""
        metadata_path = self.keys_dir / "metadata.json"
        if not metadata_path.exists():
            return None
        
        with open(metadata_path, 'r') as f:
            all_metadata = json.load(f)
        
        return all_metadata.get(key_id)
    
    def _save_metadata(self, key_id: str, metadata: Dict[str, Any]) -> None:
        """Save metadata for a key."""
        metadata_path = self.keys_dir / "metadata.json"
        
        if metadata_path.exists():
            with open(metadata_path, 'r') as f:
                all_metadata = json.load(f)
        else:
            all_metadata = {}
        
        all_metadata[key_id] = metadata
        
        with open(metadata_path, 'w') as f:
            json.dump(all_metadata, f, indent=2)
        
        os.chmod(metadata_path, 0o600)
