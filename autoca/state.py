from abc import ABC, abstractmethod
from typing import Any, Dict, Self, cast, Optional
from time import time_ns
from tomllib import load as read_toml
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509

class Deserializable(ABC):
    def from_file(self, path: str) -> Self:
        f = open(path, "ro")
        return self.from_dict(read_toml(f))

    @abstractmethod
    def from_dict(self, dict: Dict[str, Any]) -> Self:
        raise NotImplementedError()

class Serializable(ABC):
    @abstractmethod
    def to_dict(self) -> Dict[str, Any]:
        raise NotImplementedError()

class State(Serializable, Deserializable):
    def __init__(self, time=0) -> None:
        super().__init__()
        self.time = time

    def to_dict(self) -> Dict[str, Any]:
        return {
            "time": time_ns()
        }

    def from_dict(self, dict: Dict[str, Any]) -> Self:
        return self.__class__(time=int(dict["time"]))

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
            "key": self.key_bytes
        }

    def from_dict(self, dict: Dict[str, Any]) -> Self:
        data = bytes(dict["key"])
        key = cast(rsa.RSAPrivateKey, serialization.load_pem_private_key(data, None, default_backend()))
        return self.__class__(key=key)

class CA(KeyPair):
    def __init__(self, key: Optional[rsa.RSAPrivateKey] = None, sn: Optional[str] = None, start: Optional[float] = 0, end: Optional[float] = 0, certificate: Optional[x509.Certificate] = None) -> None:
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
    def start(self) -> float:
        assert self._start is not None
        return self._start

    @property
    def end(self) -> float:
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
            "start": self.start,
            "end": self.end,
            "certificate": self.certificate_bytes,
        }

    def from_dict(self, dict: Dict[str, Any]) -> Self:
        key = super().from_dict(dict).key
        sn = dict["sn"]
        start = float(dict["start"])
        end = float(dict["end"])
        certificate = x509.load_pem_x509_certificate(
            dict["certificate"], default_backend()
        )
        return self.__class__(key=key, sn=sn, start=start, end=end, certificate=certificate)

class Certificate(KeyPair):
    def __init__(self, key: Optional[rsa.RSAPrivateKey] = None, domain: Optional[str] = None, start: Optional[float] = 0, end: Optional[float] = 0, certificate: Optional[x509.Certificate] = None) -> None:
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
    def start(self) -> float:
        assert self._start is not None
        return self._start

    @property
    def end(self) -> float:
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
            "start": self.start,
            "end": self.end,
            "certificate": self.certificate_bytes,
        }

    def from_dict(self, dict: Dict[str, Any]) -> Self:
        key = super().from_dict(dict).key
        domain = dict["domain"]
        start = float(dict["start"])
        end = float(dict["end"])
        certificate = x509.load_pem_x509_certificate(
            dict["certificate"], default_backend()
        )
        return self.__class__(key=key, domain=domain, start=start, end=end, certificate=certificate)
