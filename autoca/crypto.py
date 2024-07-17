import datetime
from logging import debug
from typing import Optional, List, cast
import os
from datetime import datetime
import re
import uuid
from autoca.state import KeyPair, CA

from cryptography import x509
from cryptography.x509 import Certificate, CertificateBuilder, CertificateSigningRequestBuilder
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
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

T = CertificateBuilder | CertificateSigningRequestBuilder
def _add_SANs(builder: T, names: List[str]) -> T:
    SANs = [x509.DNSName(name) for name in names]
    builder = builder.add_extension(
        x509.SubjectAlternativeName(SANs),
        critical=False,
    )

    return builder


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
    start: int,
    end: int
) -> CA:
    issuer = sn
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, sn)]))
    builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
    # builder = _add_SANs(builder, [sn])
    builder = builder.not_valid_before(datetime.fromtimestamp(start))
    builder = builder.not_valid_after(datetime.fromtimestamp(end))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(key_pair.public_key)
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    certificate = builder.sign(private_key=key_pair.key, algorithm=hashes.SHA256(), backend=default_backend())
    return CA(key=key_pair.key, sn=sn, start=start, end=end, certificate=certificate)


def issue_csr(key: rsa.RSAPrivateKey, names: List[str]):
    cn = names[0]
    csr_builder = x509.CertificateSigningRequestBuilder()
    csr_builder = csr_builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
    csr_builder = _add_SANs(csr_builder, names)
    csr_builder = csr_builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=False)
    csr = csr_builder.sign(private_key=key, algorithm=hashes.SHA256(), backend=default_backend())

    return isinstance(csr, x509.CertificateSigningRequest)


def ca_sign_csr(ca_cert, ca_key, csr, public_key, duration: int):
    certificate = x509.CertificateBuilder()
    certificate = certificate.subject_name(csr.subject)
    certificate = _add_subjectaltnames_sign_csr(certificate, csr)
    certificate = certificate.issuer_name(ca_cert.subject)
    certificate = certificate.public_key(csr.public_key())
    certificate = certificate.serial_number(uuid.uuid4().int)
    # TODO: partition date-times in modulo
    certificate = certificate.not_valid_before(
        datetime.datetime.today() - ONE_DAY
    )
    certificate = certificate.not_valid_after(
        datetime.datetime.today() + (ONE_DAY * duration)
    )
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
            public_key
        ),
        critical=False,
    )
    certificate = certificate.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
        backend=default_backend(),
    )

    assert(isinstance(certificate, x509.Certificate))
    return certificate



def load_cert_files(
    common_name,
    key_file,
    public_key_file,
    csr_file,
    certificate_file,
):
    try:
        with open(csr_file, "rb") as csr_f:
            csr_data = csr_f.read()

        csr = x509.load_pem_x509_csr(csr_data, default_backend())
        csr_bytes = csr.public_bytes(encoding=serialization.Encoding.PEM)

    except FileNotFoundError:
        csr = None
        csr_bytes = None

    # certificate

    try:
        with open(certificate_file, "rb") as cert_f:
            cert_data = cert_f.read()

        certificate = x509.load_pem_x509_certificate(
            cert_data, default_backend()
        )
        certificate_bytes = certificate.public_bytes(
            encoding=serialization.Encoding.PEM
        )

    except FileNotFoundError:
        certificate = None
        certificate_bytes = None

    # key
    try:
        with open(key_file, "rb") as key_f:
            key_data = key_f.read()

        key = serialization.load_pem_private_key(
            key_data, password=None, backend=default_backend()
        )

        key_bytes = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    except FileNotFoundError:
        key = None
        key_bytes = None

    with open(public_key_file, "rb") as pub_key_f:
        pub_key_data = pub_key_f.read()

    public_key = serialization.load_ssh_public_key(
        pub_key_data, backend=default_backend()
    )

    public_key_bytes = public_key.public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )

    return {
        "cert": certificate,
        "cert_bytes": certificate_bytes,
        "csr": csr,
        "csr_bytes": csr_bytes,
        "key": key,
        "key_bytes": key_bytes,
        "public_key": public_key,
        "public_key_bytes": public_key_bytes
    }


# class CA:
#     def __init__(
#         self,
#         path=None,
#         common_name=None,
#         intermediate=False,
#         maximum_days=825,
#         **kwargs,
#     ):
#         """Constructor method"""
#
#         self._exp = kwargs.get("exp", 65537)
#         self._key_size = kwargs.get("key_size", 2048)
#         self._common_name = common_name
#         self._path = path
#
#     @property
#     def csr(self):
#         """Get CA Certificate Signing Request
#
#         :return: certificate class
#         :rtype: class, ``cryptography.hazmat.backends.openssl.x509.\
#             _CertificateSigningRequest``
#         """
#
#         return self._csr
#
#     @property
#     def csr_bytes(self):
#         """Get CA Certificate Signing Request in bytes
#
#         :return: certificate class
#         :rtype: bytes
#         """
#
#         return self._csr_bytes
#
#     @property
#     def cert(self):
#         """Get CA certificate
#
#         :return: certificate class
#         :rtype: class,
#             ``cryptography.hazmat.backends.openssl.x509.Certificate``
#         """
#         if (
#             self._certificate is None
#             and self.type == "Intermediate Certificate Authority"
#         ):
#             raise OwnCAIntermediate(
#                 "Intermediate Certificate Authority has not a signed "
#                 + "certificate file in CA Storage"
#             )
#
#         return self._certificate
#
#     @property
#     def cert_bytes(self):
#         """Get CA certificate in bytes
#
#         :return: certificate
#         :rtype: bytes,
#         """
#
#         return self._certificate_bytes
#
#     @property
#     def key(self):
#         """Get CA RSA Private key
#
#         :return: RSA Private Key class
#         :rtype: class,
#             ``cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey``
#         """
#         return self._key
#
#     @property
#     def key_bytes(self):
#         """Get CA RSA Private key in bytes
#
#         :return: RSA Private Key
#         :rtype: bytes
#         """
#         return self._key_bytes
#
#     @property
#     def public_key(self):
#         """Get CA RSA Public key
#
#         :return: RSA Public Key class
#         :rtype: class,
#             ``cryptography.hazmat.backends.openssl.rsa._RSAPublicKey``
#         """
#         return self._public_key
#
#     @property
#     def public_key_bytes(self):
#         """Get CA RSA Public key in bytes
#
#         :return: RSA Public Key class
#         :rtype: bytes
#         """
#         return self._public_key_bytes
#
#     @property
#     def common_name(self):
#         """
#         Get CA common name
#
#         :return: CA common name
#         :rtype: str
#         """
#
#         return self._common_name
#
#     @property
#     def hash_name(self):
#         """
#         Get the CA hash name
#
#         :return: CA hash name
#         :rtype: str
#         """
#
#         return format(
#             self._certificate._backend._lib.X509_NAME_hash(
#                 self._certificate._backend._lib.X509_get_issuer_name(
#                     self._certificate._x509
#                 )
#             ),
#             "x",
#         )
#
#     @property
#     def certificates(self):
#         """
#         Get the CA list of issued/managed certificates
#
#         :return: List of certificates (default is host/domain)
#         :rtype: list
#         """
#
#         host_cert_dir = os.path.join(self.ca_storage, CA_CERTS_DIR)
#         certificate_list = list()
#
#         for content in os.listdir(host_cert_dir):
#             if not os.path.isdir(os.path.join(host_cert_dir, content)):
#                 continue
#             certificate_list.append(content)
#
#         return certificate_list
#
#     def _update(self, cert_data):
#         """
#         Update certificate data in the instance.
#
#         :param cert_data:
#         :return: True
#         """
#
#         self._certificate = cert_data.cert
#         self._certificate_bytes = cert_data.cert_bytes
#         self._csr = cert_data.csr
#         self._csr_bytes = cert_data.csr_bytes
#         self._key = cert_data.key
#         self._key_bytes = cert_data.key_bytes
#         self._public_key = cert_data.public_key
#         self._public_key_bytes = cert_data.public_key_bytes
#
#     def initialize(
#         self,
#         common_name=None,
#         dns_names=None,
#         intermediate=False,
#         maximum_days=825,
#         exp=65537,
#         key_size=2048,
#     ):
#         """
#         Initialize the Certificate Authority (CA)
#
#         :param common_name: CA Common Name (CN)
#         :type common_name: str, required
#         :param dns_names: List of DNS names
#         :type dns_names: list of strings, optional
#         :param maximum_days: Certificate maximum days duration
#         :type maximum_days: int, default: 825
#         :param public_exponent: Public Exponent
#         :type public_exponent: int, default: 65537
#         :param intermediate: Intermediate Certificate Authority mode
#         :type intermediate: bool, default False
#         :param key_size: Key size
#         :type key_size: int, default: 2048
#
#         :return: tuple with CA certificate, CA Key and CA Public key
#         :rtype: tuple (
#             ``cryptography.x509.Certificate``,
#             ``cryptography.hazmat.backends.openssl.rsa``,
#             string public key
#             )
#         """
#
#         private_ca_key_file = os.path.join(self.ca_storage, CA_KEY)
#         public_ca_key_file = os.path.join(self.ca_storage, CA_PUBLIC_KEY)
#         certificate_file = os.path.join(self.ca_storage, CA_CERT)
#         csr_file = os.path.join(self.ca_storage, CA_CSR)
#
#         if self.current_ca_status is True:
#             cert_data = load_cert_files(
#                 common_name=common_name,
#                 key_file=private_ca_key_file,
#                 public_key_file=public_ca_key_file,
#                 csr_file=csr_file,
#                 certificate_file=certificate_file,
#             )
#
#             return cert_data
#
#         elif self.current_ca_status is False:
#             raise OwnCAInvalidFiles(self.status)
#
#         elif self.current_ca_status is None:
#             key = generate(
#                 public_exponent=exp, key_size=key_size
#             )
#
#             store_file(key.key_bytes, private_ca_key_file, False, None)
#             store_file(key.public_key_bytes, public_ca_key_file, False, None)
#
#             if intermediate is True:
#                 csr = issue_csr(
#                     key=key.key,
#                     cn=common_name,
#                     dns_names=dns_names,
#                     oids=self.oids,
#                 )
#                 csr_bytes = csr.public_bytes(
#                     encoding=serialization.Encoding.PEM
#                 )
#
#                 store_file(csr_bytes, csr_file, False, None)
#
#                 cert_data = OwncaCertData(
#                     {
#                         "cert": None,
#                         "cert_bytes": None,
#                         "csr": csr,
#                         "csr_bytes": csr_bytes,
#                         "key": key.key,
#                         "key_bytes": key.key_bytes,
#                         "public_key": key.public_key,
#                         "public_key_bytes": key.public_key_bytes
#                     }
#                 )
#
#                 return cert_data
#
#             certificate = create_ca(
#                 self.oids,
#                 maximum_days=maximum_days,
#                 key=key.key,
#                 pem_public_key=key.public_key,
#                 cn=common_name,
#                 dns_names=dns_names,
#             )
#
#             if not certificate:
#                 raise OwnCAFatalError(self.status)
#
#             else:
#                 certificate_bytes = certificate.public_bytes(
#                     encoding=serialization.Encoding.PEM
#                 )
#                 store_file(certificate_bytes, certificate_file, False, None)
#
#                 cert_data = {
#                     "cert": certificate,
#                     "cert_bytes": certificate_bytes,
#                     "key": key.key,
#                     "key_bytes": key.key_bytes,
#                     "public_key": key.public_key,
#                     "public_key_bytes": key.public_key_bytes
#                 }
#
#                 self._common_name = common_name
#                 self._update(cert_data)
#
#                 return cert_data
#
#     def issue_certificate(
#         self,
#         hostname,
#         maximum_days=825,
#         common_name=None,
#         dns_names=None,
#         oids=None,
#         public_exponent=65537,
#         key_size=2048,
#         ca=True,
#     ):
#         """
#         Issues a new certificate signed by the CA
#
#         :param hostname: Hostname
#         :type hostname: str, required
#         :param maximum_days: Certificate maximum days duration
#         :type maximum_days: int, default: 825
#         :param common_name: Common Name (CN) when loading existent certificate
#         :type common_name: str, optional
#         :param dns_names: List of DNS names
#         :type dns_names: list of strings, optional
#         :param oids: CA Object Identifiers (OIDs). The are typically seen
#             in X.509 names.
#             Allowed keys/values:
#             ``'country_name': str (two letters)``,
#             ``'locality_name': str``,
#             ``'state_or_province': str``,
#             ``'street_address': str``,
#             ``'organization_name': str``,
#             ``'organization_unit_name': str``,
#             ``'email_address': str``,
#         :type oids: dict, optional, all keys are optional
#         :param public_exponent: Public Exponent
#         :type public_exponent: int, default: 65537
#         :param key_size: Key size
#         :type key_size: int, default: 2048
#         :param ca: Certificate is CA or not.
#         :type ca: bool, default True.
#
#         :return: host object
#         :rtype: ``ownca.ownca.HostCertificate``
#         """
#         host_cert_dir = os.path.join(self.ca_storage, CA_CERTS_DIR, hostname)
#         host_key_path = os.path.join(host_cert_dir, f"{hostname}.pem")
#         host_public_path = os.path.join(host_cert_dir, f"{hostname}.pub")
#         host_csr_path = os.path.join(host_cert_dir, f"{hostname}.csr")
#         host_cert_path = os.path.join(host_cert_dir, f"{hostname}.crt")
#
#         files = {
#             "certificate": host_cert_path,
#             "key": host_key_path,
#             "public_key": host_public_path,
#         }
#
#         if common_name is None:
#             common_name = hostname
#
#         if os.path.isdir(host_cert_dir):
#             cert_data = load_cert_files(
#                 common_name=common_name,
#                 key_file=host_key_path,
#                 public_key_file=host_public_path,
#                 csr_file=host_csr_path,
#                 certificate_file=host_cert_path,
#             )
#
#         else:
#             os.mkdir(host_cert_dir)
#             key_data = keys.generate(
#                 public_exponent=public_exponent, key_size=key_size
#             )
#
#             store_file(key_data.key_bytes, host_key_path, False, 0o600)
#             store_file(
#                 key_data.public_key_bytes, host_public_path, False, None
#             )
#
#             if oids:
#                 oids = format_oids(oids)
#
#             else:
#                 oids = list()
#
#             csr = issue_csr(
#                 key=key_data.key,
#                 cn=common_name,
#                 dns_names=dns_names,
#                 oids=oids,
#                 ca=ca,
#             )
#
#             store_file(
#                 csr.public_bytes(encoding=serialization.Encoding.PEM),
#                 host_csr_path,
#                 False,
#                 None,
#             )
#
#             certificate = ca_sign_csr(
#                 self.cert,
#                 self.key,
#                 csr,
#                 key_data.public_key,
#                 duration=maximum_days,
#                 ca=ca,
#             )
#             certificate_bytes = certificate.public_bytes(
#                 encoding=serialization.Encoding.PEM
#             )
#
#             store_file(certificate_bytes, host_cert_path, False, None)
#
#             cert_data = OwncaCertData(
#                 {
#                     "cert": certificate,
#                     "cert_bytes": certificate_bytes,
#                     "key": key_data.key,
#                     "key_bytes": key_data.key_bytes,
#                     "public_key": key_data.public_key,
#                     "public_key_bytes": key_data.public_key_bytes
#                 }
#             )
#
#         host = HostCertificate(common_name, files, cert_data)
#
#         return host
#
#     def load_certificate(self, hostname):
#         """
#         Loads an existent certificate.
#
#         :param hostname: Hostname (common name)
#         :type hostname: str, required
#         :return: host object
#         :rtype: ``ownca.ownca.HostCertificate``
#         """
#         host_cert_dir = os.path.join(self.ca_storage, CA_CERTS_DIR, hostname)
#         if not os.path.isdir(host_cert_dir):
#             raise OwnCAInvalidCertificate(
#                 f"The certificate does not exist for '{hostname}'."
#             )
#
#         return self.issue_certificate(hostname)
#
#     def sign_csr(self, csr, csr_public_key, maximum_days=825):
#         """
#         Signs an Certificate Sigining Request and generates the certificates.
#
#         :param hostname: Hostname
#         :type hostname: str, required
#         :param csr: Certificate Signing Request Object
#         :param csr: class, ``cryptography.hazmat.backends.openssl.x509.\
#         _CertificateSigningRequest``
#         :type csr_public_key: RSA Public Key class
#         :rtype: class,
#             ``cryptography.hazmat.backends.openssl.rsa._RSAPublicKey``
#         :param maximum_days: Certificate maximum days duration
#         :type maximum_days: int, default: 825
#         :return: host object
#         :rtype: ``ownca.ownca.CertificateAuthority``
#         """
#         csr_subject = csr.subject.get_attributes_for_oid(
#             x509.NameOID.COMMON_NAME
#         )
#         if csr_subject is not None or len(csr_subject) == 1:
#             common_name = csr_subject[0].value
#
#         csr_public_key_bytes = csr_public_key.public_bytes(
#             serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
#         )
#         csr_bytes = csr.public_bytes(encoding=serialization.Encoding.PEM)
#         host_cert_dir = os.path.join(
#             self.ca_storage, CA_CERTS_DIR, common_name
#         )
#
#         certificate = ca_sign_csr(
#             self.cert, self.key, csr, csr_public_key, duration=maximum_days
#         )
#
#         os.mkdir(host_cert_dir)
#         host_public_path = os.path.join(host_cert_dir, f"{common_name}.pub")
#         host_csr_path = os.path.join(host_cert_dir, f"{common_name}.csr")
#         host_cert_path = os.path.join(host_cert_dir, f"{common_name}.crt")
#
#         store_file(csr_public_key_bytes, host_public_path, False, None)
#
#         certificate_bytes = certificate.public_bytes(
#             encoding=serialization.Encoding.PEM
#         )
#
#         store_file(certificate_bytes, host_cert_path, False, None)
#         store_file(csr_bytes, host_csr_path, False, None)
#
#         cert_data = OwncaCertData(
#             {
#                 "cert": certificate,
#                 "cert_bytes": certificate_bytes,
#                 "key": None,
#                 "key_bytes": None,
#                 "public_key": csr_public_key,
#                 "public_key_bytes": csr_public_key_bytes
#             }
#         )
#
#         files = {
#             "certificate": host_cert_path,
#             "key": None,
#             "public_key": host_public_path,
#         }
#
#         host = HostCertificate(common_name, files, cert_data)
#
#         return host
