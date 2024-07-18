from os.path import isfile
from datetime import datetime
from os import chmod
from typing import Any, Dict, Self, Optional, List
from logging import debug
from tomllib import load as read_toml

from autoca.primitives import Serializable, Deserializable, CA, Certificate

CA_KEY = "ca_key.pem"
CA_PUBLIC_KEY = "ca_key.pub"
CA_CSR = "ca.csr"

def store_file(
    path: str,
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

    def _update_time(self):
        self._time = datetime.now()

    @property
    def time(self) -> datetime:
        assert self._time is not None
        return self._time

    def set_ca(self, ca: CA):
        self._ca = ca
        self._update_time()

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
        self._update_time()

    def delete_certificate(self, cert: Certificate):
        assert self._certs is not None
        self._certs.remove(cert)
        self._update_time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "time": self.time.timestamp(),
            "ca": self.ca.to_dict(),
            "certs": [cert.to_dict() for cert in self.certs]
        }

    def from_dict(self, dict: Dict[str, Any]) -> Self:
        certs = list(dict["certs"])
        return self.__class__(time=datetime.fromtimestamp(float(dict["time"])), ca=CA().from_dict(dict["ca"]), certs=[Certificate().from_dict(cert) for cert in certs])

    @staticmethod
    def from_file(path: str) -> "State":
        f = open(path, "ro")
        return State().from_dict(read_toml(f))
