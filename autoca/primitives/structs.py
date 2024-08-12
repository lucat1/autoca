from hashlib import sha256
from typing import Self, TypedDict, cast, Optional
from datetime import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509

from autoca.primitives.serde import Serializable, Deserializable

class KeyPairDict(TypedDict):
    key: str

class KeyPair(Serializable[KeyPairDict], Deserializable[KeyPairDict]):
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

    def to_dict(self) -> KeyPairDict:
        return {
            "key": self.key_bytes.decode('utf-8'),
        }

    def from_dict(self, dict: KeyPairDict) -> Self:
        data = bytes(dict["key"], "utf-8")
        key = cast(rsa.RSAPrivateKey, serialization.load_pem_private_key(data, None, default_backend()))
        return self.__class__(key=key)

    @property
    def id(self) -> str:
        return sha256(self.key_bytes).hexdigest()

    def __str__(self) -> str:
        return f"{self.id[:4]}..{self.id[-4:]}"

class CADict(KeyPairDict):
    sn: str
    start: float
    end: float
    certificate: str

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

    def to_dict(self) -> CADict:
        return {
            "key": super().to_dict()["key"],
            "sn": self.sn,
            "start": self.start.timestamp(),
            "end": self.end.timestamp(),
            "certificate": self.certificate_bytes.decode('utf-8'),
        }

    def from_dict(self, dict: CADict) -> Self: # type: ignore
        key = super().from_dict(dict).key
        sn = dict["sn"]
        start = datetime.fromtimestamp(float(dict["start"]))
        end = datetime.fromtimestamp(float(dict["end"]))
        certificate = x509.load_pem_x509_certificate(
            bytes(dict["certificate"], 'utf-8'), default_backend()
        )
        return self.__class__(key=key, sn=sn, start=start, end=end, certificate=certificate)

    def __str__(self) -> str:
        return f"{self.id[:4]}..{self.id[-4:]}\t{self.sn}\t{self.start}\t{self.end}"

class CertificateDict(KeyPairDict):
    domain: str
    start: float
    end: float
    certificate: str
    user: str

class Certificate(KeyPair):
    def __init__(self, key: Optional[rsa.RSAPrivateKey] = None, domain: Optional[str] = None, start: Optional[datetime] = None, end: Optional[datetime] = None, certificate: Optional[x509.Certificate] = None, user: Optional[str] = None) -> None:
        super().__init__(key)
        self._domain = domain
        self._start = start
        self._end = end
        self._certificate = certificate
        self._user = user

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
    def expired(self) -> bool:
        return self.end <= datetime.now()

    @property
    def certificate(self) -> x509.Certificate:
        assert self._certificate is not None
        return self._certificate

    @property
    def certificate_bytes(self) -> bytes:
        return self.certificate.public_bytes(
            encoding=serialization.Encoding.PEM
        )
    
    @property
    def user(self) -> str:
        assert self._user is not None
        return self._user

    def to_dict(self) -> CertificateDict:
        return {
            "key": super().to_dict()["key"],
            "domain": self.domain,
            "start": self.start.timestamp(),
            "end": self.end.timestamp(),
            "certificate": self.certificate_bytes.decode('utf-8'),
            "user": self.user,
        }

    def from_dict(self, dict: CertificateDict) -> Self: # type: ignore
        key = super().from_dict(dict).key
        domain = dict["domain"]
        start = datetime.fromtimestamp(float(dict["start"]))
        end = datetime.fromtimestamp(float(dict["end"]))
        certificate = x509.load_pem_x509_certificate(
            bytes(dict["certificate"], 'utf-8'), default_backend()
        )
        user = dict["user"]
        return self.__class__(key=key, domain=domain, start=start, end=end, certificate=certificate, user=user)

    def __str__(self) -> str:
        return f"{self.id[:4]}..{self.id[-4:]}\t{self.domain}\t{self.start}\t\t{self.end}"

class LinkDict(TypedDict):
    host: bool
    name: str
    id: str

class Link(Serializable[LinkDict], Deserializable[LinkDict]):
    def __init__(self, host: Optional[bool] = None, name: Optional[str] = None, id: Optional[str] = None) -> None:
        self._host = host
        self._name = name
        self._id = id

    @property
    def host(self) -> bool:
        assert self._host is not None
        return self._host

    @property
    def name(self) -> str:
        assert self._name is not None
        return self._name

    @property
    def id(self) -> str:
        assert self._id is not None
        return self._id

    def same_src(self, other: Self) -> bool:
        return self.host == other.host and self.name == other.name

    def to_dict(self) -> LinkDict:
        return {
            "host": self.host,
            "name": self.name,
            "id": self.id,
        }

    def from_dict(self, dict: LinkDict) -> Self:
        host = dict["host"]
        name = dict["name"]
        id = dict["id"]
        return self.__class__(host=host, name=name, id=id)

    def __str__(self) -> str:
        return f"{self.name} ({self.host})\t\t->\t{self.id[:4]}..{self.id[-4:]}"
