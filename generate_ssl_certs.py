"""
SSL Certificate Generator
=========================
Generates self-signed SSL certificates for development/testing.

For production, use certificates from a trusted Certificate Authority (CA)
like Let's Encrypt, DigiCert, or your organization's internal CA.
"""

import os
from pathlib import Path
from datetime import datetime, timedelta

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("ERROR: 'cryptography' library required. Run: pip install cryptography")
    exit(1)


def generate_self_signed_cert(
    cert_path: str = "ssl/cert.pem",
    key_path: str = "ssl/key.pem",
    common_name: str = "localhost",
    organization: str = "IoT Botnet Detection",
    validity_days: int = 365,
    key_size: int = 2048
):
    """
    Generate a self-signed SSL certificate.
    
    Args:
        cert_path: Path to save certificate
        key_path: Path to save private key
        common_name: Certificate CN (usually domain name)
        organization: Organization name
        validity_days: Certificate validity period
        key_size: RSA key size in bits
    """
    print("=" * 60)
    print("🔐 SSL CERTIFICATE GENERATOR")
    print("=" * 60)
    
    # Create directories
    Path(cert_path).parent.mkdir(parents=True, exist_ok=True)
    
    # Generate RSA private key
    print("\n📝 Generating RSA private key...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    print(f"✅ Generated {key_size}-bit RSA key")
    
    # Certificate subject
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Build certificate
    print("📝 Building certificate...")
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("127.0.0.1"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    
    # Save private key
    print(f"💾 Saving private key to {key_path}...")
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    os.chmod(key_path, 0o600)  # Restrict permissions
    
    # Save certificate
    print(f"💾 Saving certificate to {cert_path}...")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print("\n" + "=" * 60)
    print("✅ SSL CERTIFICATES GENERATED SUCCESSFULLY!")
    print("=" * 60)
    print(f"\n📄 Certificate: {cert_path}")
    print(f"🔑 Private Key: {key_path}")
    print(f"📅 Valid For: {validity_days} days")
    print(f"🏢 Organization: {organization}")
    print(f"🌐 Common Name: {common_name}")
    print("\n⚠️  NOTE: This is a SELF-SIGNED certificate for development.")
    print("    For production, use certificates from a trusted CA.")
    print("=" * 60)


import ipaddress

if __name__ == '__main__':
    generate_self_signed_cert()
