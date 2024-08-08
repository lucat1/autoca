from typing import Any, Dict, Self, cast, Optional
from datetime import datetime
from pathlib import Path
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from logging import debug, info, error

from autoca.primitives.serde import Serializable, Deserializable
from autoca.primitives.utils import check_write_file

class KeyPair(Serializable, Deserializable):
    KEY_ENCODNIG = serialization.Encoding.PEM
    KEY_FORMAT = serialization.PrivateFormat.PKCS8
    KEY_ENCRYPTION = serialization.NoEncryption()

    PUBLIC_KEY_ENCODNIG = serialization.Encoding.OpenSSH
    PUBLIC_KEY_FORMAT = serialization.PublicFormat.OpenSSH

    def __init__(self, key: Optional[rsa.RSAPrivateKey] = None) -> None:
        self._key = key

    @property
    def key(self) -> rsa.RSAPrivateKey:
        assert self._key is not None
        return self._key

    @property
    def key_bytes(self) -> bytes:
        return self.key.private_bytes(
            self.KEY_ENCODNIG,
            self.KEY_FORMAT,
            self.KEY_ENCRYPTION,
        )

    @property
    def public_key(self) -> rsa.RSAPublicKey:
        return self.key.public_key()

    @property
    def public_key_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            self.PUBLIC_KEY_ENCODNIG,
            self.PUBLIC_KEY_FORMAT 
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key_bytes.decode('utf-8'),
        }

    def from_dict(self, dict: Dict[str, Any]) -> Self:
        data = bytes(dict["key"], "utf-8")
        key = cast(rsa.RSAPrivateKey, serialization.load_pem_private_key(data, None, default_backend()))
        return self.__class__(key=key)

class CA(KeyPair):
    def __init__(self, key: Optional[rsa.RSAPrivateKey] = None, sn: Optional[str] = None, start: Optional[datetime] = None, end: Optional[datetime] = None, certificate: Optional[x509.Certificate] = None) -> None:
        super().__init__(key)
        self._sn = sn
        self._start = start
        self._end = end
        self._certificate = certificate

    @property
    def sn(self) -> str:
        assert self._sn is not None
        return self._sn

    @property
    def start(self) -> datetime:
        assert self._start is not None
        return self._start

    @property
    def end(self) -> datetime:
        assert self._end is not None
        return self._end

    @property
    def certificate(self) -> x509.Certificate:
        assert self._certificate is not None
        return self._certificate

    @property
    def certificate_bytes(self) -> bytes:
        return self.certificate.public_bytes(
            encoding=serialization.Encoding.PEM
        )

    def to_dict(self) -> Dict[str, Any]:
        return super().to_dict() | {
            "sn": self.sn,
            "start": self.start.timestamp(),
            "end": self.end.timestamp(),
            "certificate": self.certificate_bytes.decode('utf-8'),
        }

    def from_dict(self, dict: Dict[str, Any]) -> Self:
        key = super().from_dict(dict).key
        sn = dict["sn"]
        start = datetime.fromtimestamp(float(dict["start"]))
        end = datetime.fromtimestamp(float(dict["end"]))
        certificate = x509.load_pem_x509_certificate(
            bytes(dict["certificate"], 'utf-8'), default_backend()
        )
        return self.__class__(key=key, sn=sn, start=start, end=end, certificate=certificate)

class Certificate(KeyPair):
    def __init__(self, key: Optional[rsa.RSAPrivateKey] = None, domain: Optional[str] = None, start: Optional[datetime] = None, end: Optional[datetime] = None, certificate: Optional[x509.Certificate] = None) -> None:
        super().__init__(key)
        self._domain = domain
        self._start = start
        self._end = end
        self._certificate = certificate

    @property
    def domain(self) -> str:
        assert self._domain is not None
        return self._domain

    @property
    def start(self) -> datetime:
        assert self._start is not None
        return self._start

    @property
    def end(self) -> datetime:
        assert self._end is not None
        return self._end

    @property
    def certificate(self) -> x509.Certificate:
        assert self._certificate is not None
        return self._certificate

    @property
    def certificate_bytes(self) -> bytes:
        return self.certificate.public_bytes(
            encoding=serialization.Encoding.PEM
        )

    def to_dict(self) -> Dict[str, Any]:
        return super().to_dict() | {
            "domain": self.domain,
            "start": self.start.timestamp(),
            "end": self.end.timestamp(),
            "certificate": self.certificate_bytes.decode('utf-8'),
        }

    def from_dict(self, dict: Dict[str, Any]) -> Self:
        key = super().from_dict(dict).key
        domain = dict["domain"]
        start = datetime.fromtimestamp(float(dict["start"]))
        end = datetime.fromtimestamp(float(dict["end"]))
        certificate = x509.load_pem_x509_certificate(
            bytes(dict["certificate"], 'utf-8'), default_backend()
        )
        return self.__class__(key=key, domain=domain, start=start, end=end, certificate=certificate)
