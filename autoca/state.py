from datetime import datetime
from pathlib import Path
from os import getuid, makedirs, chown
from os.path import relpath
from getpass import getuser
from typing import Any, Dict, Self, Optional, List, Union
from logging import info, error
from tomllib import load as read_toml
from tomli_w import dumps as write_toml
from hashlib import sha256
from grp import getgrnam, struct_group

from autoca.primitives import Serializable, Deserializable, CA, Certificate
from autoca.primitives.utils import check_write_file, create_symlink_if_not_present, File

CA_KEY = "ca_key.pem"
CA_PUBLIC_KEY = "ca_key.pub"
CA_CSR = "ca.csr"

def _write_or_print_error( path: Path, content: bytes, 
                          permissions: Optional[File] = None):
    try:
        check_write_file(path, content, permissions)
    except:
        import traceback
        error("Could not check/write %s. %r", path, traceback.format_exc())

class State(Serializable, Deserializable):
    def __init__(self, time: Optional[datetime] = None, ca: Optional[CA] = None, certs: Optional[List[tuple[Certificate, File]]] = None) -> None:
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
    def certs(self) -> List[tuple[Certificate, File]]:
        assert self._certs is not None
        return self._certs

    def add_certificate(self, cert: Certificate, perm: File):
        if self._certs is None:
            self._certs = []
        self._certs.append([cert, perm])
        self._updated()

    def delete_certificate(self, cert: Certificate):
        assert self._certs is not None
        tmp = [x for x in self._certs if x[0].domain != cert.domain]
        self._certs = tmp
        self._updated()

    @property
    def initialized(self) -> bool:
        return self._ca is not None and self._certs is not None and self._time is not None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "time": self.time.timestamp(),
            "ca": self.ca.to_dict(),
            "certs": [(cert[0].to_dict(), cert[1].to_dict()) for cert in self.certs]
        }

    def to_file(self, path: Path):
        b = bytes(write_toml(self.to_dict()), "utf-8")
        check_write_file(path, b, File(0o600, getuser(), getuser()))

    def from_dict(self, dict: Dict[str, Any]) -> Self:
        certs = list(dict["certs"])
        time = datetime.fromtimestamp(float(dict["time"]))
        ca = CA().from_dict(dict["ca"])
        certs = [(Certificate().from_dict(cert[0]), File().from_dict(cert[1])) for cert in certs]
        return self.__class__(time=time, ca=ca, certs=certs)

    @staticmethod
    def from_file(path: Path) -> "State":
        f = open(path, "rb")
        return State().from_dict(read_toml(f))

    def update_fs(self, old_state: Self | None, path: Path, grp: struct_group):
        certs_dir_path = path.joinpath("certs")
        makedirs(certs_dir_path, exist_ok=True)
        chown(certs_dir_path, getuid(), grp.gr_gid)

        hosts_dir_path = path.joinpath("hosts")
        makedirs(hosts_dir_path, exist_ok=True)
        chown(hosts_dir_path, getuid(), grp.gr_gid)

        if old_state == None or self.ca != old_state.ca:
            self.cert_to_files(certs_dir_path, (self.ca, File(0o660, "root", "root")), path, grp)

        if old_state == None:
            return

        for c in self.certs:
            if c not in old_state.certs:
                info("Writing cert for domain %s", c[0].domain)
                self.cert_to_files(certs_dir_path, c, hosts_dir_path, grp)

    @staticmethod
    def cert_to_files(cert_path: Path, cert: tuple[Certificate | CA, File], link_path: Path, grp: struct_group):
        if isinstance(cert[0], CA):
            name = "ca"
            p = cert[1]
        else:
            # Hardcoding the certs group for .crt and .pub files
            name = cert[0].domain
            p = File(cert[1].permissions, cert[1].user, grp.gr_name)

        sha = sha256(cert[0].key_bytes).hexdigest()

        cert_path = cert_path.joinpath(sha)
        makedirs(cert_path, exist_ok=True)
        _write_or_print_error(cert_path.joinpath("cert.crt"), cert[0].certificate_bytes, p)
        _write_or_print_error(cert_path.joinpath("cert.key"), cert[0].key_bytes, cert[1])
        _write_or_print_error(cert_path.joinpath("cert.pub"), cert[0].public_key_bytes, p)

        create_symlink_if_not_present(Path(relpath(cert_path, link_path)), link_path.joinpath(name), target_is_directory=True)
