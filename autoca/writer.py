from grp import getgrnam
from logging import error
from enum import Enum
from pathlib import Path
from os import chown
from dataclasses import dataclass
from typing import Set

from autoca.primitives.structs import CA, Certificate, Link

SUPER_UID = 0
SUPER_GID = 0

CERTS_DIR = "certs"
CERTS_MODE = 0o750
HOSTS_DIR = "hosts"
HOSTS_MODE = 0o750

CRT_FILE = "cert.crt"
CRT_MODE = 0o640
PUB_FILE = "cert.pub"
PUB_MODE = 0o640
KEY_FILE = "cert.key"
KEY_MODE_CERT = 0o640
KEY_MODE_CA = 0o600

@dataclass
class Permission:
    mode: int
    user: int
    group: int

class ChangeKind(Enum):
    create = 'create'
    delete = 'delete'

@dataclass(frozen=True)
class Change:
    kind: ChangeKind
    entity: CA | Certificate | Link

    def __str__(self) -> str:
        return f"{self.kind.value}\t\t{self.entity}"

class Writer:
    def __init__(self, root: Path, shared_gid: int) -> None:
        self._root = root
        self._shared_gid = shared_gid

    def get_gid(self, group: str) -> int:
        grp = getgrnam(group)
        return grp.gr_gid

    def create_certificate(self, cert: CA | Certificate) -> None:
        path = self._root.joinpath(CERTS_DIR, cert.id)
        gid = self.get_gid(cert.user) if isinstance(cert, Certificate) else SUPER_GID

        path.mkdir(CERTS_MODE, parents=True)
        chown(path, SUPER_UID, self._shared_gid)

        crt_path = path.joinpath(CRT_FILE)
        crt_path.touch(CRT_MODE, exist_ok=False)
        chown(crt_path, SUPER_UID, self._shared_gid)
        crt_path.write_bytes(cert.certificate_bytes)

        pub_path = path.joinpath(PUB_FILE)
        pub_path.touch(PUB_MODE, exist_ok=False)
        chown(pub_path, SUPER_UID, self._shared_gid)
        pub_path.write_bytes(cert.public_key_bytes)
        
        key_path = path.joinpath(KEY_FILE)
        key_path.touch(KEY_MODE_CA if isinstance(cert, CA) else KEY_MODE_CERT, exist_ok=False)
        chown(key_path, SUPER_UID, gid)
        key_path.write_bytes(cert.key_bytes)

    def create_link(self, link: Link) -> None:
        if link.host:
            parent_path = self._root.joinpath(HOSTS_DIR)
            parent_path.mkdir(HOSTS_MODE, parents=True, exist_ok=True)
            chown(parent_path, SUPER_UID, self._shared_gid)
        else:
            parent_path = self._root

        link_path = parent_path.joinpath(link.name)
        link_to = self._root.joinpath(CERTS_DIR, link.id).relative_to(parent_path, walk_up=True)
        if link_path.exists():
            link_path.unlink()
        link_path.symlink_to(link_to, target_is_directory=True)

    def apply(self, change: Change) -> None:
        match change.kind:
            case ChangeKind.create:
                match change.entity:
                    case CA():
                        self.create_certificate(change.entity)
                    case Certificate():
                        self.create_certificate(change.entity)
                    case Link():
                        self.create_link(change.entity)
                    case other:
                        error('Cannot handle the creation of unkown entity %r', type(other))

            case ChangeKind.delete:
                raise NotImplementedError()

    def apply_many(self, changes: Set[Change]) -> None:
        for change in changes:
            self.apply(change)
