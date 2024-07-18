import datetime
from logging import debug
from typing import Optional, List, cast
import os
from datetime import datetime
import re
import uuid
from autoca.state import KeyPair, CA, Certificate

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

CA_KEY = "ca_key.pem"
CA_PUBLIC_KEY = "ca_key.pub"
CA_CSR = "ca.csr"
HOSTNAME_REGEX = "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"

def store_file(
    path: str,
    data: bytes,
    force: bool,
    permission: Optional[int],
):
    if os.path.isfile(path) and force is False:
        debug(f"Avoiding overwriting file {path}")

    with open(path, "w") as f:
        f.write(data.decode("utf-8"))

    if permission is not None:
        os.chmod(path, permission)

def generate_keypair(public_exponent=65537, key_size=4096) -> KeyPair:
    key = rsa.generate_private_key(
        backend=default_backend(),
        public_exponent=public_exponent,
        key_size=key_size,
    )
    return KeyPair(key)

def _add_subjectaltnames_sign_csr(builder, csr):
    """
    Adds to the certificate (during singing CSR) the SubjectAltNames.

    :param builder: certificate builder
    :type builder: ``cryptography.x509.CertificateBuilder()``, required
    :param csr: CSR object
    :type csr: ``cryptography.x509.CertificateSigningRequest``, required
    :return: builder object
    :rtype: ``cryptography.x509.CertificateBuilder()``
    """
    for extension in csr.extensions:
        if extension.value.oid._name != "subjectAltName":
            continue

        builder = builder.add_extension(
            extension.value, critical=extension.critical
        )

    return builder


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
    # builder = _add_SANs(builder, [sn])
    builder = builder.not_valid_before(start)
    builder = builder.not_valid_after(end)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(key_pair.public_key)
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    certificate = builder.sign(private_key=key_pair.key, algorithm=hashes.SHA256(), backend=default_backend())
    return CA(key=key_pair.key, sn=sn, start=start.timestamp(), end=end.timestamp(), certificate=certificate)

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
    # builder = _add_SANs(builder, [sn])
    builder = builder.not_valid_before(start)
    builder = builder.not_valid_after(end)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(key_pair.public_key)
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    certificate = builder.sign(private_key=key_pair.key, algorithm=hashes.SHA256(), backend=default_backend())
    assert(isinstance(certificate, x509.Certificate))
    return CA(key=key_pair.key, sn=sn, start=start.timestamp(), end=end.timestamp(), certificate=certificate)


def generate_csr(key_pair: KeyPair, domain: str) -> x509.CertificateSigningRequest:
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


def sign_csr(ca: CA, csr: x509.CertificateSigningRequest, start: datetime, end: datetime) -> x509.Certificate:
    certificate = x509.CertificateBuilder()
    certificate = certificate.subject_name(csr.subject)
    certificate = _add_subjectaltnames_sign_csr(certificate, csr)
    certificate = certificate.issuer_name(ca.certificate.subject)
    certificate = certificate.public_key(csr.public_key())
    certificate = certificate.serial_number(uuid.uuid4().int)
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

def create_certificate(key_pair: KeyPair, ca: CA, domain: str, start: datetime, end: datetime) -> Certificate:
    csr = generate_csr(key_pair, domain)
    certificate = sign_csr(ca, csr, start, end)
    return Certificate(key=key_pair.key, domain=domain, start=start.timestamp(), end=end.timestamp(), certificate=certificate)
