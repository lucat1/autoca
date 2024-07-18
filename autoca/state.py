from os.path import isfile
from datetime import datetime
from pathlib import Path
from os import chmod
from typing import Any, Dict, Self, Optional, List
from logging import debug
from tomllib import load as read_toml
from tomli_w import dumps as write_toml

from autoca.primitives import Serializable, Deserializable, CA, Certificate

CA_KEY = "ca_key.pem"
CA_PUBLIC_KEY = "ca_key.pub"
CA_CSR = "ca.csr"

def write_file(
    path: Path,
    data: bytes,
    force: bool,
    permission: Optional[int],
):
    if isfile(path) and force is False:
        debug(f"Avoiding overwriting file {path}")
        return

    with open(path, "w") as f:
        f.write(data.decode("utf-8"))

    if permission is not None:
        chmod(path, permission)

class State(Serializable, Deserializable):
    def __init__(self, time: Optional[datetime] = None, ca: Optional[CA] = None, certs: Optional[List[Certificate]] = None) -> None:
        super().__init__()
        self._time = time
        self._ca = ca
        self._certs = certs

    def _updated(self):
        self._time = datetime.now()
        if self._certs is None:
            self._certs = []

    @property
    def time(self) -> datetime:
        assert self._time is not None
        return self._time

    def set_ca(self, ca: CA):
        self._ca = ca
        self._updated()

    @property
    def ca(self) -> CA:
        assert self._ca is not None
        return self._ca

    @property
    def certs(self) -> List[Certificate]:
        assert self._certs is not None
        return self._certs

    def add_certificate(self, cert: Certificate):
        if self._certs is None:
            self._certs = []
        self._certs.append(cert)
        self._updated()

    def delete_certificate(self, cert: Certificate):
        assert self._certs is not None
        self._certs.remove(cert)
        self._updated()

    @property
    def initialized(self) -> bool:
        return self._ca is not None and self._certs is not None and self._time is not None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "time": self.time.timestamp(),
            "ca": self.ca.to_dict(),
            "certs": [cert.to_dict() for cert in self.certs]
        }

    def to_file(self, path: Path):
        import stat
        b = bytes(write_toml(self.to_dict()), "utf-8")
        write_file(path, b, True, stat.S_IRUSR | stat.S_IWUSR)

    def from_dict(self, dict: Dict[str, Any]) -> Self:
        certs = list(dict["certs"])
        time = datetime.fromtimestamp(float(dict["time"]))
        ca = CA().from_dict(dict["ca"])
        certs = [Certificate().from_dict(cert) for cert in certs]
        return self.__class__(time=time, ca=ca, certs=certs)

    @staticmethod
    def from_file(path: Path) -> "State":
        f = open(path, "rb")
        return State().from_dict(read_toml(f))
