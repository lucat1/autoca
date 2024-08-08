from os.path import isfile
from datetime import datetime
from pathlib import Path
from os import chmod, makedirs, symlink
from typing import Any, Dict, Self, Optional, List, Union
from logging import debug, info, error
from tomllib import load as read_toml
from tomli_w import dumps as write_toml
from hashlib import sha256

from autoca.primitives import Serializable, Deserializable, CA, Certificate
from autoca.primitives.utils import check_write_file, create_symlink_if_not_present

CA_KEY = "ca_key.pem"
CA_PUBLIC_KEY = "ca_key.pub"
CA_CSR = "ca.csr"

def _write_or_print_error( path: Path, content: bytes, 
                          permissions: Optional[int] = None):
    try:
        check_write_file(path, content)
    except:
        import traceback
        error("Could not check/write %s. %r", path, traceback.format_exc())


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
        check_write_file(path, b, stat.S_IRUSR | stat.S_IWUSR)

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


    def __cert_to_files(self, path: Path, cert: Union[Certificate, CA]):
        makedirs(path, exist_ok=True)
        _write_or_print_error(path.joinpath("cert.crt"), cert.certificate_bytes)
        _write_or_print_error(path.joinpath("cert.key"), cert.key_bytes)
        _write_or_print_error(path.joinpath("cert.pub"), cert.public_key_bytes)
        

    def certs_to_files(self, path: Path):
        certs_dir_path = path.joinpath("certs")
        makedirs(certs_dir_path, exist_ok=True)
        hosts_dir_path = path.joinpath("hosts")
        makedirs(hosts_dir_path, exist_ok=True)

        # CA to file
        sha = sha256(self.ca.sn.encode()).hexdigest()
        self.__cert_to_files(certs_dir_path.joinpath(sha), self.ca)
        create_symlink_if_not_present(Path("certs/").joinpath(sha), 
                    path.joinpath("ca"), target_is_directory=True)

        for cert in self.certs:
            sha = sha256(cert.domain.encode()).hexdigest()
            self.__cert_to_files(certs_dir_path.joinpath(sha), cert)
            create_symlink_if_not_present(Path("../certs/").joinpath(sha), 
                    hosts_dir_path.joinpath(cert.domain), target_is_directory=True)
