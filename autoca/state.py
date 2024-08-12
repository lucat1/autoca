from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, List, Self, Optional, Set, TypedDict, cast
from tomllib import load as read_toml
from tomli_w import dumps as write_toml

from autoca.primitives import Serializable, Deserializable, CA, CADict, Certificate, CertificateDict, Link, LinkDict
from autoca.writer import SUPER_GID, SUPER_UID, Change, ChangeKind, Permission, write_safely

CA_DIR = "ca"

class StateDict(TypedDict):
    time: float
    ca: CADict
    certs: List[CertificateDict]
    links: List[LinkDict]

class State(Serializable[StateDict], Deserializable):
    def __init__(self, time: Optional[datetime] = None, ca: Optional[CA] = None, certs: Optional[Set[Certificate]] = None, links: Optional[Set[Link]] = None) -> None:
        super().__init__()
        self._time = time
        self._ca = ca
        self._certs = certs
        self._links = links

    def _updated(self):
        self._time = datetime.now()
        if self._certs is None:
            self._certs = set()
        if self._links is None:
            self._links = set()

    def _add_link(self, link: Link):
        if self._links is None:
            self._links = set()

        self._links = set(l for l in self.links if not link.same_src(l))
        self._links.add(link)

    @property
    def time(self) -> datetime:
        assert self._time is not None
        return self._time

    def set_ca(self, ca: CA):
        self._ca = ca
        self._add_link(Link(False, CA_DIR, sha256(ca.key_bytes).hexdigest()))
        self._updated()

    @property
    def ca(self) -> CA:
        assert self._ca is not None
        return self._ca

    @property
    def certs(self) -> Set[Certificate]:
        return self._certs or set()

    def certs_by_domain(self, domain: str) -> Set[Certificate]:
        return set(cert for cert in self.certs if cert.domain == domain)

    def most_recent(self, domain: str) -> Certificate:
        certs = self.certs_by_domain(domain)
        assert len(certs) > 0
        return sorted(certs, reverse=True, key=lambda cert: cert.end)[0]

    @property
    def links(self) -> Set[Link]:
        return self._links or set()

    def add_certificate(self, cert: Certificate):
        if self._certs is None:
            self._certs = set()

        self._certs.add(cert)
        if self.most_recent(cert.domain) == cert:
            self._add_link(Link(True, cert.domain, sha256(cert.key_bytes).hexdigest()))
        self._updated()

    def remove_certificate(self, cert: Certificate):
        assert self._certs is not None
        self._certs.remove(cert)
        self._updated()

    @property
    def initialized(self) -> bool:
        return self._ca is not None and self._certs is not None and self._time is not None and self._links is not None

    def to_dict(self) -> StateDict:
        return {
            "time": self.time.timestamp(),
            "ca": self.ca.to_dict(),
            "certs": [cert.to_dict() for cert in self.certs],
            "links": [link.to_dict() for link in self.links],
        }

    def to_file(self, path: Path):
        d = cast(Dict[str, Any], self.to_dict())
        b = bytes(write_toml(d), "utf-8")
        write_safely(path, b, Permission(0o600, SUPER_UID, SUPER_GID), True)

    def from_dict(self, dict: StateDict) -> Self:
        time = datetime.fromtimestamp(float(dict["time"]))
        ca = CA().from_dict(dict["ca"])
        certs = set(Certificate().from_dict(cert) for cert in dict["certs"])
        links = set(Link().from_dict(link) for link in dict["links"])
        return self.__class__(time=time, ca=ca, certs=certs, links=links)

    @staticmethod
    def from_file(path: Path) -> "State":
        f = open(path, "rb")
        return State().from_dict(cast(StateDict, read_toml(f)))

    def clone(self) -> "State":
        # Deep copy can't be done as RSAPrivateKey cannot be pickled
        return State().from_dict(self.to_dict()) if self.initialized else State()

    def diff(self, other: Self) -> Set[Change]:
        changes = set()

        if not other.initialized or self.ca != other.ca:
            changes.add(Change(ChangeKind.create, self.ca))

        for cert in self.certs:
            if cert not in other.certs:
                changes.add(Change(ChangeKind.create, cert))

        for cert in other.certs:
            if cert not in self.certs:
                changes.add(Change(ChangeKind.delete, cert))

        for link in self.links:
            if link not in other.links:
                changes.add(Change(ChangeKind.create, link))

        for link in other.links:
            if not any(l for l in self.links if link.same_src(l)):
                changes.add(Change(ChangeKind.delete, link))

        return changes
