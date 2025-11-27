# Encryption Strategy for IoT Botnet Detection System

## Overview

This document outlines the comprehensive encryption strategy implemented for the IoT Botnet Detection project to protect data confidentiality while maintaining system availability and performance.

## Security Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     CLIENT (Browser/API)                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ HTTPS/TLS 1.3
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     FLASK APPLICATION                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ Rate Limiter │  │ API Key Auth │  │ Sec Headers  │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
┌──────────────────┐ ┌──────────────┐ ┌──────────────────┐
│  Encrypted ML    │ │  Encrypted   │ │  Key Management  │
│  Model Storage   │ │  Dataset     │ │  System          │
│  (AES-256-GCM)   │ │  (AES-256)   │ │  (PBKDF2)        │
└──────────────────┘ └──────────────┘ └──────────────────┘
```

## Encryption Methods

### 1. Data at Rest

#### Algorithm: AES-256-GCM
- **Key Size**: 256 bits (32 bytes)
- **Mode**: Galois/Counter Mode (GCM)
- **IV/Nonce**: 96 bits (12 bytes), unique per encryption
- **Authentication Tag**: 128 bits (16 bytes)

**Why AES-256-GCM?**
- Provides both confidentiality AND integrity (authenticated encryption)
- Tamper detection - any modification is detected
- Hardware acceleration on modern CPUs (AES-NI)
- NIST approved, widely audited

#### What's Encrypted:
| Data Type | Encryption | Location |
|-----------|------------|----------|
| ML Model (.pkl) | AES-256-GCM | `encrypted_models/` |
| Scaler | AES-256-GCM | `encrypted_models/` |
| Feature Columns | AES-256-GCM | `encrypted_models/` |
| IoT Dataset | AES-256-GCM | `encrypted_data/` |
| API Keys | SHA-256 Hash | Memory/Database |
| Session Data | AES-256-GCM | Server-side |

### 2. Data in Transit

#### Protocol: TLS 1.3 (minimum TLS 1.2)
- **Certificate**: RSA 2048-bit or ECDSA P-256
- **Key Exchange**: ECDHE (Ephemeral Diffie-Hellman)
- **Cipher Suites**: ECDHE+AESGCM, DHE+AESGCM, ECDHE+CHACHA20

**Security Headers Applied:**
```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
Strict-Transport-Security: max-age=31536000; includeSubDomains
Referrer-Policy: strict-origin-when-cross-origin
```

## Key Management

### Key Hierarchy
```
Master Key (derived from password or HSM)
    │
    ├── Data Encryption Key (DEK) - for datasets
    ├── Model Encryption Key (MEK) - for ML models
    ├── API Key Signing Key - for API authentication
    └── Session Key - for session data
```

### Key Derivation (PBKDF2)
- **Algorithm**: PBKDF2-HMAC-SHA256
- **Iterations**: 600,000 (OWASP 2023 recommendation)
- **Salt**: 256 bits (32 bytes), cryptographically random

### Key Rotation Policy
| Key Type | Rotation Period | Max Age |
|----------|-----------------|---------|
| Data Keys | 90 days | 365 days |
| Model Keys | 90 days | 365 days |
| API Keys | On compromise | 365 days |
| Session Keys | Per session | 30 minutes |

### Key Storage
- **Development**: Encrypted files with master key
- **Production**: AWS KMS, HashiCorp Vault, or Azure Key Vault

## Implementation Guide

### 1. Install Dependencies

```bash
pip install cryptography flask pandas scikit-learn joblib pyarrow
```

### 2. Initialize Security

```python
from security.config import get_security_config
from security.key_manager import KeyManager

config = get_security_config()
key_manager = KeyManager(config)
key_manager.initialize_master_key()
```

### 3. Encrypt Data

```python
from security.encryption import DataEncryptor

encryptor = DataEncryptor(key_manager=key_manager)

# Encrypt string
encrypted = encryptor.encrypt_string("sensitive data")

# Encrypt file
encryptor.encrypt_file("data/iot_dataset.csv", "encrypted_data/iot_dataset.enc")

# Encrypt DataFrame
encrypted_df = encryptor.encrypt_dataframe(df)
```

### 4. Secure Model Storage

```python
from security.secure_storage import SecureModelStorage

storage = SecureModelStorage(key_manager=key_manager)

# Save encrypted model
metadata = storage.save_model(
    model=trained_model,
    model_id='botnet_model',
    additional_files={'scaler': scaler}
)

# Load encrypted model
model, metadata = storage.load_model('botnet_model')
```

### 5. Generate SSL Certificates

```bash
# Development (self-signed)
python generate_ssl_certs.py

# Production (Let's Encrypt)
certbot certonly --standalone -d yourdomain.com
```

### 6. Run Secure Server

```bash
# Development
python app_secure.py

# Production
SSL_ENABLED=true python app_secure.py
```

## API Authentication

### Generating API Keys

```python
from app_secure import register_api_key

api_key = register_api_key("client_name")
print(f"API Key: {api_key}")  # Store securely!
```

### Using API Keys

```bash
# Header method (recommended)
curl -H "X-API-Key: your_api_key" https://localhost:5000/api/admin/stats

# Query parameter method
curl "https://localhost:5000/api/admin/stats?api_key=your_api_key"
```

## Performance Considerations

### Encryption Overhead

| Operation | Overhead | Mitigation |
|-----------|----------|------------|
| AES-256-GCM | ~5% CPU | AES-NI hardware acceleration |
| TLS Handshake | ~100ms first request | Session resumption, keep-alive |
| Key Derivation | ~500ms | Cache derived keys |
| File Encryption | ~10% I/O | Streaming encryption, chunking |

### Availability Measures

1. **No Single Point of Failure**
   - Key backups with encrypted export
   - Model versioning for rollback
   - Health check endpoints

2. **Graceful Degradation**
   - Falls back to unencrypted if secure storage unavailable
   - Rate limiting prevents DoS

3. **Performance Optimization**
   - Key caching in memory
   - Streaming encryption for large files
   - Async model loading

## Compliance Mapping

| Requirement | Implementation |
|-------------|----------------|
| **GDPR Art. 32** | AES-256-GCM encryption at rest |
| **NIST 800-53 SC-8** | TLS 1.3 for data in transit |
| **NIST 800-53 SC-12** | PBKDF2 key derivation, rotation |
| **PCI DSS 3.4** | Encrypted storage of sensitive data |
| **SOC 2 CC6.1** | Access controls, API authentication |

## Security Checklist

- [ ] Install `cryptography` library
- [ ] Initialize key manager with secure master key
- [ ] Generate SSL certificates
- [ ] Enable HTTPS in production
- [ ] Configure API key authentication
- [ ] Set up key rotation schedule
- [ ] Test encrypted model loading
- [ ] Enable security headers
- [ ] Configure rate limiting
- [ ] Set up monitoring/alerting

## File Structure

```
iot-botnet-project/
├── security/
│   ├── __init__.py          # Security module exports
│   ├── config.py            # Security configuration
│   ├── key_manager.py       # Key generation/rotation
│   ├── encryption.py        # AES-256-GCM encryption
│   └── secure_storage.py    # Encrypted model storage
├── keys/                    # Encryption keys (gitignore!)
├── ssl/                     # SSL certificates (gitignore!)
├── encrypted_models/        # Encrypted ML models
├── encrypted_data/          # Encrypted datasets
├── app_secure.py           # Secure Flask application
├── train_model_secure.py   # Secure model training
├── generate_ssl_certs.py   # SSL certificate generator
└── SECURITY.md             # This document
```

## Troubleshooting

### "cryptography library required"
```bash
pip install cryptography
```

### "SSL certificate not found"
```bash
python generate_ssl_certs.py
```

### "Invalid API key"
- Verify API key is being sent correctly
- Check key hasn't been rotated
- Ensure using correct endpoint

### "Rate limit exceeded"
- Wait for rate limit window to expire
- Request rate limit increase for legitimate use

## Future Enhancements

1. **Hardware Security Module (HSM)** integration
2. **Envelope encryption** for large datasets
3. **Certificate pinning** for mobile clients
4. **Audit logging** with tamper-evident logs
5. **Zero-knowledge proofs** for privacy-preserving ML
