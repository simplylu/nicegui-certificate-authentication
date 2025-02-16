from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import Name, NameAttribute, CertificateBuilder, SubjectAlternativeName
import cryptography.x509
import datetime
import random


def get_certificate(username: str, password: str) -> bytes:
    pk = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend
    )

    subject = Name([
        NameAttribute(cryptography.x509.NameOID.COUNTRY_NAME, u"US"),
        NameAttribute(cryptography.x509.NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        NameAttribute(cryptography.x509.NameOID.LOCALITY_NAME, u"San Francisco"),
        NameAttribute(cryptography.x509.NameOID.ORGANIZATION_NAME, u"NicePFXLogin"),
        NameAttribute(cryptography.x509.NameOID.COMMON_NAME, u"local.host")
    ])
    issuer = subject

    certificate = CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).not_valid_before(
        datetime.datetime.now(datetime.UTC)
    ).not_valid_after(
        datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)
    ).serial_number(
        random.randint(1, 2**63 - 1)
    ).public_key(
        pk.public_key()
    ).add_extension(
        SubjectAlternativeName([cryptography.x509.DNSName(u"local.host")]),
        critical=False
    ).sign(pk, hashes.SHA256(), default_backend())

    pfx_bytes = serialization.pkcs12.serialize_key_and_certificates(
        name=username.encode(),
        key=pk,
        cert=certificate,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )

    return pfx_bytes


def authenticate(password: str, certificate: bytes) -> bool:
    try:
        pk, cert, additional_certs = load_key_and_certificates(
            certificate,
            password=password.encode(),
            backend=default_backend()
        )
        return True
    except Exception as ex:
        print(f"Exception: {ex}")
        return False
