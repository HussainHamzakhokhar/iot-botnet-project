"""
Secure Model Storage Module
===========================
Encrypts machine learning models and associated files for secure storage.

Security Features:
- Encrypted model serialization
- Integrity verification with checksums
- Model versioning and audit trail
- Secure temporary file handling
"""

import os
import json
import hashlib
import tempfile
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass, asdict

try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False

from .config import SecurityConfig, get_security_config
from .key_manager import KeyManager
from .encryption import DataEncryptor


@dataclass
class ModelMetadata:
    """Metadata for an encrypted model."""
    model_id: str
    model_type: str
    version: int
    created_at: str
    encrypted_at: str
    checksum_sha256: str
    key_id: str
    file_size: int
    features_count: int
    accuracy: Optional[float] = None
    description: str = ""


class SecureModelStorage:
    """
    Securely stores and retrieves machine learning models.
    
    Features:
    - AES-256-GCM encryption for model files
    - SHA-256 checksums for integrity verification
    - Automatic key rotation support
    - Model versioning
    """
    
    MODEL_EXTENSION = ".enc"
    METADATA_FILE = "models_metadata.json"
    
    def __init__(
        self,
        storage_dir: str = "encrypted_models",
        key_manager: Optional[KeyManager] = None,
        config: Optional[SecurityConfig] = None
    ):
        """
        Initialize secure model storage.
        
        Args:
            storage_dir: Directory for encrypted models
            key_manager: KeyManager for encryption keys
            config: Security configuration
        """
        self.config = config or get_security_config()
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize key manager
        self.key_manager = key_manager or KeyManager(self.config)
        self.key_manager.initialize_master_key()
        
        # Get or create model encryption key
        self._key_id, key = self.key_manager.get_active_key("model")
        if key is None:
            self._key_id, key = self.key_manager.generate_key("model")
        
        self.encryptor = DataEncryptor(key=key, config=self.config)
    
    def save_model(
        self,
        model: Any,
        model_id: str,
        model_type: str = "sklearn",
        description: str = "",
        accuracy: Optional[float] = None,
        additional_files: Optional[Dict[str, Any]] = None
    ) -> ModelMetadata:
        """
        Encrypt and save a machine learning model.
        
        Args:
            model: The model object (sklearn, joblib-compatible)
            model_id: Unique identifier for the model
            model_type: Type of model (sklearn, pytorch, tensorflow)
            description: Model description
            accuracy: Model accuracy metric
            additional_files: Additional files to encrypt (scaler, features, etc.)
            
        Returns:
            ModelMetadata for the saved model
        """
        if not JOBLIB_AVAILABLE:
            raise RuntimeError("joblib required for model storage")
        
        # Create temporary directory for serialization
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Serialize model to temporary file
            temp_model_path = temp_path / "model.pkl"
            joblib.dump(model, temp_model_path)
            
            # Calculate checksum of original model
            checksum = self._calculate_checksum(temp_model_path)
            
            # Read and encrypt model
            with open(temp_model_path, 'rb') as f:
                model_bytes = f.read()
            
            encrypted_model = self.encryptor.encrypt(model_bytes)
            
            # Determine version
            version = self._get_next_version(model_id)
            
            # Save encrypted model
            encrypted_path = self.storage_dir / f"{model_id}_v{version}{self.MODEL_EXTENSION}"
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_model)
            os.chmod(encrypted_path, 0o600)
            
            # Handle additional files
            features_count = 0
            if additional_files:
                for file_name, file_data in additional_files.items():
                    if file_name == 'feature_columns':
                        features_count = len(file_data) if hasattr(file_data, '__len__') else 0
                    
                    # Serialize and encrypt additional file
                    temp_file = temp_path / f"{file_name}.pkl"
                    joblib.dump(file_data, temp_file)
                    
                    with open(temp_file, 'rb') as f:
                        file_bytes = f.read()
                    
                    encrypted_file = self.encryptor.encrypt(file_bytes)
                    
                    # Save encrypted file
                    encrypted_file_path = self.storage_dir / f"{model_id}_v{version}_{file_name}{self.MODEL_EXTENSION}"
                    with open(encrypted_file_path, 'wb') as f:
                        f.write(encrypted_file)
                    os.chmod(encrypted_file_path, 0o600)
            
            # Create metadata
            metadata = ModelMetadata(
                model_id=model_id,
                model_type=model_type,
                version=version,
                created_at=datetime.utcnow().isoformat(),
                encrypted_at=datetime.utcnow().isoformat(),
                checksum_sha256=checksum,
                key_id=self._key_id,
                file_size=len(encrypted_model),
                features_count=features_count,
                accuracy=accuracy,
                description=description
            )
            
            # Save metadata
            self._save_metadata(metadata)
            
            return metadata
    
    def load_model(
        self,
        model_id: str,
        version: Optional[int] = None
    ) -> Tuple[Any, ModelMetadata]:
        """
        Load and decrypt a model.
        
        Args:
            model_id: Model identifier
            version: Specific version (latest if None)
            
        Returns:
            Tuple of (model, metadata)
        """
        if not JOBLIB_AVAILABLE:
            raise RuntimeError("joblib required for model storage")
        
        # Get metadata
        metadata = self._get_metadata(model_id, version)
        if metadata is None:
            raise ValueError(f"Model {model_id} not found")
        
        # Load encrypted model
        encrypted_path = self.storage_dir / f"{model_id}_v{metadata.version}{self.MODEL_EXTENSION}"
        with open(encrypted_path, 'rb') as f:
            encrypted_model = f.read()
        
        # Decrypt model
        model_bytes = self.encryptor.decrypt(encrypted_model)
        
        # Verify checksum
        checksum = hashlib.sha256(model_bytes).hexdigest()
        if checksum != metadata.checksum_sha256:
            raise ValueError("Model integrity check failed - file may be corrupted")
        
        # Deserialize model
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pkl') as temp_file:
            temp_file.write(model_bytes)
            temp_path = temp_file.name
        
        try:
            model = joblib.load(temp_path)
        finally:
            os.unlink(temp_path)
        
        return model, metadata
    
    def load_additional_file(
        self,
        model_id: str,
        file_name: str,
        version: Optional[int] = None
    ) -> Any:
        """
        Load an additional encrypted file associated with a model.
        
        Args:
            model_id: Model identifier
            file_name: Name of the additional file
            version: Specific version (latest if None)
            
        Returns:
            Decrypted file contents
        """
        if not JOBLIB_AVAILABLE:
            raise RuntimeError("joblib required")
        
        metadata = self._get_metadata(model_id, version)
        if metadata is None:
            raise ValueError(f"Model {model_id} not found")
        
        encrypted_path = self.storage_dir / f"{model_id}_v{metadata.version}_{file_name}{self.MODEL_EXTENSION}"
        if not encrypted_path.exists():
            raise ValueError(f"File {file_name} not found for model {model_id}")
        
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_bytes = self.encryptor.decrypt(encrypted_data)
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pkl') as temp_file:
            temp_file.write(decrypted_bytes)
            temp_path = temp_file.name
        
        try:
            return joblib.load(temp_path)
        finally:
            os.unlink(temp_path)
    
    def list_models(self) -> list[ModelMetadata]:
        """
        List all stored models.
        
        Returns:
            List of model metadata
        """
        metadata_path = self.storage_dir / self.METADATA_FILE
        if not metadata_path.exists():
            return []
        
        with open(metadata_path, 'r') as f:
            all_metadata = json.load(f)
        
        return [ModelMetadata(**m) for m in all_metadata.values()]
    
    def delete_model(self, model_id: str, version: Optional[int] = None) -> bool:
        """
        Delete a model (specific version or all versions).
        
        Args:
            model_id: Model identifier
            version: Specific version to delete (all if None)
            
        Returns:
            True if deleted successfully
        """
        metadata_path = self.storage_dir / self.METADATA_FILE
        if not metadata_path.exists():
            return False
        
        with open(metadata_path, 'r') as f:
            all_metadata = json.load(f)
        
        deleted = False
        keys_to_delete = []
        
        for key, meta in all_metadata.items():
            if meta['model_id'] == model_id:
                if version is None or meta['version'] == version:
                    keys_to_delete.append(key)
                    
                    # Delete encrypted files
                    pattern = f"{model_id}_v{meta['version']}*{self.MODEL_EXTENSION}"
                    for file_path in self.storage_dir.glob(pattern):
                        file_path.unlink()
                    
                    deleted = True
        
        for key in keys_to_delete:
            del all_metadata[key]
        
        with open(metadata_path, 'w') as f:
            json.dump(all_metadata, f, indent=2)
        
        return deleted
    
    def verify_integrity(self, model_id: str, version: Optional[int] = None) -> bool:
        """
        Verify model integrity using stored checksum.
        
        Args:
            model_id: Model identifier
            version: Specific version to verify
            
        Returns:
            True if integrity check passes
        """
        try:
            model, metadata = self.load_model(model_id, version)
            return True
        except ValueError:
            return False
    
    def _calculate_checksum(self, file_path: Path) -> str:
        """Calculate SHA-256 checksum of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def _get_next_version(self, model_id: str) -> int:
        """Get the next version number for a model."""
        metadata_path = self.storage_dir / self.METADATA_FILE
        if not metadata_path.exists():
            return 1
        
        with open(metadata_path, 'r') as f:
            all_metadata = json.load(f)
        
        max_version = 0
        for meta in all_metadata.values():
            if meta['model_id'] == model_id:
                max_version = max(max_version, meta['version'])
        
        return max_version + 1
    
    def _save_metadata(self, metadata: ModelMetadata) -> None:
        """Save model metadata."""
        metadata_path = self.storage_dir / self.METADATA_FILE
        
        if metadata_path.exists():
            with open(metadata_path, 'r') as f:
                all_metadata = json.load(f)
        else:
            all_metadata = {}
        
        key = f"{metadata.model_id}_v{metadata.version}"
        all_metadata[key] = asdict(metadata)
        
        with open(metadata_path, 'w') as f:
            json.dump(all_metadata, f, indent=2)
    
    def _get_metadata(self, model_id: str, version: Optional[int] = None) -> Optional[ModelMetadata]:
        """Get metadata for a specific model."""
        metadata_path = self.storage_dir / self.METADATA_FILE
        if not metadata_path.exists():
            return None
        
        with open(metadata_path, 'r') as f:
            all_metadata = json.load(f)
        
        if version is not None:
            key = f"{model_id}_v{version}"
            if key in all_metadata:
                return ModelMetadata(**all_metadata[key])
            return None
        
        # Get latest version
        latest = None
        latest_version = 0
        for meta in all_metadata.values():
            if meta['model_id'] == model_id and meta['version'] > latest_version:
                latest = meta
                latest_version = meta['version']
        
        return ModelMetadata(**latest) if latest else None
