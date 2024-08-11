import datetime
from datetime import datetime
from uuid import uuid4

from autoca.primitives import KeyPair, CA, Certificate

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

def generate_keypair(public_exponent=65537, key_size=4096) -> KeyPair:
    key = rsa.generate_private_key(
        backend=default_backend(),
        public_exponent=public_exponent,
        key_size=key_size,
    )
    return KeyPair(key)

def create_ca(
    key_pair: KeyPair,
    sn: str,
    start: datetime,
    end: datetime
) -> CA:
    issuer = sn
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, sn)]))
    builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(sn)]),
        critical=False,
    )
    builder = builder.not_valid_before(start)
    builder = builder.not_valid_after(end)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(key_pair.public_key)
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    certificate = builder.sign(private_key=key_pair.key, algorithm=hashes.SHA256(), backend=default_backend())
    return CA(key=key_pair.key, sn=sn, start=start, end=end, certificate=certificate)

def sign_cert(
    key_pair: KeyPair,
    sn: str,
    start: datetime,
    end: datetime
) -> CA:
    issuer = sn
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, sn)]))
    builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(sn)]),
        critical=False,
    )
    builder = builder.not_valid_before(start)
    builder = builder.not_valid_after(end)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(key_pair.public_key)
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    certificate = builder.sign(private_key=key_pair.key, algorithm=hashes.SHA256(), backend=default_backend())
    assert(isinstance(certificate, x509.Certificate))
    return CA(key=key_pair.key, sn=sn, start=start, end=end, certificate=certificate)


def _generate_csr(key_pair: KeyPair, domain: str) -> x509.CertificateSigningRequest:
    csr_builder = x509.CertificateSigningRequestBuilder()
    csr_builder = csr_builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
    csr_builder = csr_builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(domain)]),
        critical=False,
    )
    csr_builder = csr_builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=False)
    csr = csr_builder.sign(private_key=key_pair.key, algorithm=hashes.SHA256(), backend=default_backend())

    assert isinstance(csr, x509.CertificateSigningRequest)
    return csr


def _sign_csr(ca: CA, csr: x509.CertificateSigningRequest, start: datetime, end: datetime) -> x509.Certificate:
    certificate = x509.CertificateBuilder()
    certificate = certificate.subject_name(csr.subject)
    for extension in csr.extensions:
        if extension.value.oid._name != "subjectAltName":
            continue

        certificate = certificate.add_extension(
            extension.value, critical=extension.critical
        )
    certificate = certificate.issuer_name(ca.certificate.subject)
    certificate = certificate.public_key(csr.public_key())
    certificate = certificate.serial_number(uuid4().int)
    certificate = certificate.not_valid_before(start)
    certificate = certificate.not_valid_after(end)
    certificate = certificate.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=True,
            data_encipherment=False,
            key_agreement=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=False,
        ),
        critical=True,
    )
    certificate = certificate.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )
    certificate = certificate.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(
            csr.public_key()
        ),
        critical=False,
    )
    certificate = certificate.sign(
        private_key=ca.key,
        algorithm=hashes.SHA256(),
        backend=default_backend(),
    )

    assert isinstance(certificate, x509.Certificate)
    return certificate

def create_certificate(key_pair: KeyPair, ca: CA, domain: str, start: datetime, end: datetime, user: str) -> Certificate:
    csr = _generate_csr(key_pair, domain)
    certificate = _sign_csr(ca, csr, start, end)
    return Certificate(key=key_pair.key, domain=domain, start=start, end=end, certificate=certificate, user=user)
