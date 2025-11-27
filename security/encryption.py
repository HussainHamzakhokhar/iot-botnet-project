"""
Data Encryption Module
======================
Provides encryption/decryption for data at rest using AES-256-GCM.

Security Features:
- AES-256-GCM authenticated encryption (confidentiality + integrity)
- Unique IV/nonce for each encryption operation
- Authentication tag verification
- Streaming encryption for large files
- DataFrame encryption for IoT data
"""

import os
import json
import struct
from io import BytesIO
from pathlib import Path
from typing import Optional, Union, BinaryIO, Tuple
from base64 import b64encode, b64decode

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, hmac
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("WARNING: 'cryptography' library not installed. Run: pip install cryptography")

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

from .config import SecurityConfig, get_security_config
from .key_manager import KeyManager


class DataEncryptor:
    """
    Encrypts and decrypts data using AES-256-GCM.
    
    AES-256-GCM provides:
    - Confidentiality: Data cannot be read without the key
    - Integrity: Tampering with encrypted data is detected
    - Authenticity: Verifies data came from a trusted source
    """
    
    # File format constants
    MAGIC_BYTES = b'IOTENC'  # File signature
    VERSION = 1
    HEADER_SIZE = 8  # magic (6) + version (2)
    CHUNK_SIZE = 64 * 1024  # 64KB chunks for streaming
    
    def __init__(
        self, 
        key: Optional[bytes] = None,
        key_manager: Optional[KeyManager] = None,
        config: Optional[SecurityConfig] = None
    ):
        """
        Initialize the encryptor.
        
        Args:
            key: Encryption key (256 bits / 32 bytes)
            key_manager: KeyManager for automatic key handling
            config: Security configuration
        """
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library required. Run: pip install cryptography")
        
        self.config = config or get_security_config()
        self.key_manager = key_manager
        self._key = key
        self._key_id: Optional[str] = None
        
        if key is None and key_manager:
            # Get or generate key from manager
            self._key_id, self._key = key_manager.get_active_key("data")
            if self._key is None:
                self._key_id, self._key = key_manager.generate_key("data")
    
    @property
    def key(self) -> bytes:
        """Get the encryption key."""
        if self._key is None:
            raise ValueError("No encryption key available")
        return self._key
    
    def encrypt(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Encrypt data using AES-256-GCM.
        
        Args:
            plaintext: Data to encrypt
            associated_data: Additional authenticated data (not encrypted but authenticated)
            
        Returns:
            Encrypted data (nonce + ciphertext + tag)
        """
        # Generate unique nonce for this encryption
        nonce = os.urandom(self.config.iv_size_bytes)
        
        # Create AESGCM cipher
        aesgcm = AESGCM(self.key)
        
        # Encrypt (ciphertext includes authentication tag)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        
        # Return nonce + ciphertext
        return nonce + ciphertext
    
    def decrypt(self, ciphertext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt data using AES-256-GCM.
        
        Args:
            ciphertext: Encrypted data (nonce + ciphertext + tag)
            associated_data: Additional authenticated data used during encryption
            
        Returns:
            Decrypted plaintext
            
        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails
        """
        # Extract nonce
        nonce = ciphertext[:self.config.iv_size_bytes]
        actual_ciphertext = ciphertext[self.config.iv_size_bytes:]
        
        # Create AESGCM cipher
        aesgcm = AESGCM(self.key)
        
        # Decrypt and verify
        return aesgcm.decrypt(nonce, actual_ciphertext, associated_data)
    
    def encrypt_string(self, plaintext: str, encoding: str = 'utf-8') -> str:
        """
        Encrypt a string and return base64-encoded result.
        
        Args:
            plaintext: String to encrypt
            encoding: String encoding
            
        Returns:
            Base64-encoded encrypted data
        """
        encrypted = self.encrypt(plaintext.encode(encoding))
        return b64encode(encrypted).decode('ascii')
    
    def decrypt_string(self, ciphertext: str, encoding: str = 'utf-8') -> str:
        """
        Decrypt a base64-encoded encrypted string.
        
        Args:
            ciphertext: Base64-encoded encrypted data
            encoding: String encoding
            
        Returns:
            Decrypted string
        """
        encrypted = b64decode(ciphertext.encode('ascii'))
        decrypted = self.decrypt(encrypted)
        return decrypted.decode(encoding)
    
    def encrypt_json(self, data: dict) -> str:
        """
        Encrypt a JSON-serializable object.
        
        Args:
            data: Dictionary to encrypt
            
        Returns:
            Base64-encoded encrypted JSON
        """
        json_bytes = json.dumps(data, separators=(',', ':')).encode('utf-8')
        encrypted = self.encrypt(json_bytes)
        return b64encode(encrypted).decode('ascii')
    
    def decrypt_json(self, ciphertext: str) -> dict:
        """
        Decrypt a JSON object.
        
        Args:
            ciphertext: Base64-encoded encrypted JSON
            
        Returns:
            Decrypted dictionary
        """
        encrypted = b64decode(ciphertext.encode('ascii'))
        decrypted = self.decrypt(encrypted)
        return json.loads(decrypted.decode('utf-8'))
    
    def encrypt_file(self, input_path: Union[str, Path], output_path: Union[str, Path]) -> None:
        """
        Encrypt a file using streaming encryption.
        
        Args:
            input_path: Path to plaintext file
            output_path: Path for encrypted output
        """
        input_path = Path(input_path)
        output_path = Path(output_path)
        
        # Generate file-level nonce
        file_nonce = os.urandom(self.config.iv_size_bytes)
        
        with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            # Write header
            outfile.write(self.MAGIC_BYTES)
            outfile.write(struct.pack('>H', self.VERSION))
            outfile.write(file_nonce)
            
            # Encrypt file in chunks
            chunk_num = 0
            while True:
                chunk = infile.read(self.CHUNK_SIZE)
                if not chunk:
                    break
                
                # Derive chunk-specific nonce
                chunk_nonce = self._derive_chunk_nonce(file_nonce, chunk_num)
                
                # Encrypt chunk
                aesgcm = AESGCM(self.key)
                encrypted_chunk = aesgcm.encrypt(chunk_nonce, chunk, None)
                
                # Write chunk size + encrypted chunk
                outfile.write(struct.pack('>I', len(encrypted_chunk)))
                outfile.write(encrypted_chunk)
                
                chunk_num += 1
        
        # Set restrictive permissions
        os.chmod(output_path, 0o600)
    
    def decrypt_file(self, input_path: Union[str, Path], output_path: Union[str, Path]) -> None:
        """
        Decrypt a file using streaming decryption.
        
        Args:
            input_path: Path to encrypted file
            output_path: Path for decrypted output
        """
        input_path = Path(input_path)
        output_path = Path(output_path)
        
        with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            # Read and verify header
            magic = infile.read(6)
            if magic != self.MAGIC_BYTES:
                raise ValueError("Invalid encrypted file format")
            
            version = struct.unpack('>H', infile.read(2))[0]
            if version != self.VERSION:
                raise ValueError(f"Unsupported file version: {version}")
            
            file_nonce = infile.read(self.config.iv_size_bytes)
            
            # Decrypt chunks
            chunk_num = 0
            while True:
                size_data = infile.read(4)
                if not size_data:
                    break
                
                chunk_size = struct.unpack('>I', size_data)[0]
                encrypted_chunk = infile.read(chunk_size)
                
                # Derive chunk-specific nonce
                chunk_nonce = self._derive_chunk_nonce(file_nonce, chunk_num)
                
                # Decrypt chunk
                aesgcm = AESGCM(self.key)
                decrypted_chunk = aesgcm.decrypt(chunk_nonce, encrypted_chunk, None)
                
                outfile.write(decrypted_chunk)
                chunk_num += 1
    
    def encrypt_dataframe(self, df: 'pd.DataFrame') -> bytes:
        """
        Encrypt a pandas DataFrame.
        
        Args:
            df: DataFrame to encrypt
            
        Returns:
            Encrypted bytes
        """
        if not PANDAS_AVAILABLE:
            raise RuntimeError("pandas required for DataFrame encryption")
        
        # Serialize DataFrame to bytes
        buffer = BytesIO()
        df.to_parquet(buffer, index=False)
        plaintext = buffer.getvalue()
        
        # Encrypt
        return self.encrypt(plaintext)
    
    def decrypt_dataframe(self, ciphertext: bytes) -> 'pd.DataFrame':
        """
        Decrypt a pandas DataFrame.
        
        Args:
            ciphertext: Encrypted DataFrame bytes
            
        Returns:
            Decrypted DataFrame
        """
        if not PANDAS_AVAILABLE:
            raise RuntimeError("pandas required for DataFrame decryption")
        
        # Decrypt
        plaintext = self.decrypt(ciphertext)
        
        # Deserialize DataFrame
        buffer = BytesIO(plaintext)
        return pd.read_parquet(buffer)
    
    def _derive_chunk_nonce(self, file_nonce: bytes, chunk_num: int) -> bytes:
        """Derive a unique nonce for each chunk."""
        # XOR file nonce with chunk number
        chunk_bytes = chunk_num.to_bytes(self.config.iv_size_bytes, 'big')
        return bytes(a ^ b for a, b in zip(file_nonce, chunk_bytes))


class FieldEncryptor:
    """
    Encrypt individual fields for database storage.
    Useful for encrypting specific columns while keeping others queryable.
    """
    
    def __init__(self, encryptor: DataEncryptor):
        self.encryptor = encryptor
    
    def encrypt_field(self, value: any) -> str:
        """
        Encrypt a single field value.
        
        Args:
            value: Value to encrypt (will be JSON serialized)
            
        Returns:
            Base64-encoded encrypted value
        """
        json_value = json.dumps(value)
        return self.encryptor.encrypt_string(json_value)
    
    def decrypt_field(self, encrypted: str) -> any:
        """
        Decrypt a single field value.
        
        Args:
            encrypted: Base64-encoded encrypted value
            
        Returns:
            Decrypted value
        """
        json_value = self.encryptor.decrypt_string(encrypted)
        return json.loads(json_value)
    
    def encrypt_sensitive_columns(
        self, 
        df: 'pd.DataFrame', 
        columns: list[str]
    ) -> 'pd.DataFrame':
        """
        Encrypt specific columns in a DataFrame.
        
        Args:
            df: DataFrame with sensitive data
            columns: List of column names to encrypt
            
        Returns:
            DataFrame with encrypted columns
        """
        if not PANDAS_AVAILABLE:
            raise RuntimeError("pandas required")
        
        result = df.copy()
        for col in columns:
            if col in result.columns:
                result[col] = result[col].apply(self.encrypt_field)
        
        return result
    
    def decrypt_sensitive_columns(
        self, 
        df: 'pd.DataFrame', 
        columns: list[str]
    ) -> 'pd.DataFrame':
        """
        Decrypt specific columns in a DataFrame.
        
        Args:
            df: DataFrame with encrypted columns
            columns: List of column names to decrypt
            
        Returns:
            DataFrame with decrypted columns
        """
        if not PANDAS_AVAILABLE:
            raise RuntimeError("pandas required")
        
        result = df.copy()
        for col in columns:
            if col in result.columns:
                result[col] = result[col].apply(self.decrypt_field)
        
        return result


class HMACVerifier:
    """
    HMAC-based integrity verification for data.
    
    Provides cryptographic proof that data has not been modified.
    Uses HMAC-SHA256 for strong integrity guarantees.
    """
    
    def __init__(self, key: bytes):
        """
        Initialize HMAC verifier.
        
        Args:
            key: Secret key for HMAC (should be at least 32 bytes)
        """
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library required")
        self.key = key
    
    def generate_hmac(self, data: bytes) -> bytes:
        """
        Generate HMAC-SHA256 for data.
        
        Args:
            data: Data to authenticate
            
        Returns:
            32-byte HMAC
        """
        h = hmac.HMAC(self.key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        return h.finalize()
    
    def verify_hmac(self, data: bytes, signature: bytes) -> bool:
        """
        Verify HMAC-SHA256 signature.
        
        Args:
            data: Original data
            signature: HMAC to verify
            
        Returns:
            True if valid, False otherwise
        """
        h = hmac.HMAC(self.key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        try:
            h.verify(signature)
            return True
        except InvalidSignature:
            return False
    
    def sign_message(self, message: bytes) -> bytes:
        """
        Sign a message (append HMAC).
        
        Args:
            message: Message to sign
            
        Returns:
            Message with HMAC appended (message + 32-byte HMAC)
        """
        mac = self.generate_hmac(message)
        return message + mac
    
    def verify_and_extract(self, signed_message: bytes) -> tuple[bool, bytes]:
        """
        Verify and extract message from signed data.
        
        Args:
            signed_message: Message with HMAC appended
            
        Returns:
            Tuple of (is_valid, original_message)
        """
        if len(signed_message) < 32:
            return False, b''
        
        message = signed_message[:-32]
        mac = signed_message[-32:]
        
        is_valid = self.verify_hmac(message, mac)
        return is_valid, message if is_valid else b''


class RSAEncryptor:
    """
    RSA asymmetric encryption for key exchange and small data.
    
    Use cases:
    - Encrypting symmetric keys for secure key exchange
    - Digital signatures for non-repudiation
    - Encrypting small amounts of data (< key size)
    
    Note: For large data, use AES (symmetric) and encrypt the AES key with RSA.
    """
    
    def __init__(self, private_key: bytes = None, public_key: bytes = None):
        """
        Initialize RSA encryptor.
        
        Args:
            private_key: PEM-encoded private key (for decryption/signing)
            public_key: PEM-encoded public key (for encryption/verification)
        """
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library required")
        
        self._private_key = None
        self._public_key = None
        
        if private_key:
            self._private_key = serialization.load_pem_private_key(
                private_key, password=None, backend=default_backend()
            )
            self._public_key = self._private_key.public_key()
        elif public_key:
            self._public_key = serialization.load_pem_public_key(
                public_key, backend=default_backend()
            )
    
    @classmethod
    def generate_keypair(cls, key_size: int = 2048) -> tuple[bytes, bytes]:
        """
        Generate RSA key pair.
        
        Args:
            key_size: Key size in bits (2048 or 4096 recommended)
            
        Returns:
            Tuple of (private_key_pem, public_key_pem)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt data with RSA-OAEP.
        
        Args:
            plaintext: Data to encrypt (max ~190 bytes for 2048-bit key)
            
        Returns:
            Encrypted data
        """
        if self._public_key is None:
            raise ValueError("Public key required for encryption")
        
        return self._public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt data with RSA-OAEP.
        
        Args:
            ciphertext: Encrypted data
            
        Returns:
            Decrypted plaintext
        """
        if self._private_key is None:
            raise ValueError("Private key required for decryption")
        
        return self._private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def sign(self, message: bytes) -> bytes:
        """
        Create digital signature using RSA-PSS.
        
        Args:
            message: Message to sign
            
        Returns:
            Digital signature
        """
        if self._private_key is None:
            raise ValueError("Private key required for signing")
        
        return self._private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    
    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Verify digital signature.
        
        Args:
            message: Original message
            signature: Signature to verify
            
        Returns:
            True if valid, False otherwise
        """
        if self._public_key is None:
            raise ValueError("Public key required for verification")
        
        try:
            self._public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False


class HybridEncryptor:
    """
    Hybrid encryption combining RSA and AES.
    
    Uses RSA to encrypt AES keys, and AES to encrypt data.
    This provides the security of asymmetric encryption with
    the performance of symmetric encryption.
    
    Ideal for:
    - Encrypting large files for specific recipients
    - Secure key exchange
    - End-to-end encryption
    """
    
    def __init__(self, rsa_encryptor: RSAEncryptor):
        """
        Initialize hybrid encryptor.
        
        Args:
            rsa_encryptor: RSAEncryptor with appropriate keys
        """
        self.rsa = rsa_encryptor
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt data using hybrid encryption.
        
        Args:
            plaintext: Data to encrypt
            
        Returns:
            Encrypted package (RSA-encrypted AES key + AES-encrypted data)
        """
        # Generate random AES key
        aes_key = os.urandom(32)
        
        # Encrypt AES key with RSA
        encrypted_key = self.rsa.encrypt(aes_key)
        
        # Encrypt data with AES-GCM
        nonce = os.urandom(12)
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        # Package: key_length (2 bytes) + encrypted_key + nonce + ciphertext
        key_len = len(encrypted_key)
        return struct.pack('>H', key_len) + encrypted_key + nonce + ciphertext
    
    def decrypt(self, package: bytes) -> bytes:
        """
        Decrypt hybrid-encrypted data.
        
        Args:
            package: Encrypted package
            
        Returns:
            Decrypted plaintext
        """
        # Parse package
        key_len = struct.unpack('>H', package[:2])[0]
        encrypted_key = package[2:2+key_len]
        nonce = package[2+key_len:2+key_len+12]
        ciphertext = package[2+key_len+12:]
        
        # Decrypt AES key with RSA
        aes_key = self.rsa.decrypt(encrypted_key)
        
        # Decrypt data with AES-GCM
        aesgcm = AESGCM(aes_key)
        return aesgcm.decrypt(nonce, ciphertext, None)
