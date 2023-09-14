import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
from typing import Tuple

def generate_self_cert( service_name: str, k8s_namespace: str = 'default') -> Tuple[Ed25519PrivateKey, x509.Certificate]:
    key = Ed25519PrivateKey.generate()
    subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Virginia"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Richmond"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Kubernetes"),
    x509.NameAttribute(NameOID.COMMON_NAME, f"${service_name}.${k8s_namespace}.svc.local"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
    issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(f"${service_name}.${k8s_namespace}.svc.local")
        ]),
        critical=False,
    ).sign(key, hashes.SHA256())

    return (key, cert)
