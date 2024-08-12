from logging import error
from enum import Enum
from pathlib import Path
from os import chmod, chown
from os.path import exists
from dataclasses import dataclass
from typing import Set

from autoca.primitives.structs import CA, Certificate, Link

SUPER_UID = 0
SUPER_GID = 0

@dataclass
class Permission:
    mode: int
    user: int
    group: int

def write_safely(path: Path, content: bytes, permission: Permission, overwrite = False):
    if exists(path) and not overwrite:
        error("Attempted to overwrite a file %s", path)
        return

    crt = open(path, "wb")
    crt.write(content)
    crt.close()

    if permission is not None:
        chown(path, permission.user, permission.group)
        chmod(path, permission.mode)

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

    def create_certificate(self, cert: CA | Certificate) -> None:
        raise NotImplementedError()

    def create_link(self, link: Link) -> None:
        raise NotImplementedError()

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
