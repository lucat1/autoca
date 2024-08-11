from logging import error
from enum import Enum
from pathlib import Path
from os import chmod, chown
from os.path import exists
from dataclasses import dataclass
from typing import Set, Callable

from autoca.primitives.structs import CA, Certificate

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
    update = 'update'
    delete = 'delete'

@dataclass(frozen=True)
class Change:
    kind: ChangeKind
    entity: CA | Certificate

    def __str__(self) -> str:
        return f"{self.kind}\t\t{self.entity}"

Checker = Callable[[Change], bool]
def filter_changes(f: Checker, changes: Set[Change]) -> Set[Change]:
    return set(change for change in changes if f(change))

class Writer:
    def __init__(self, shared_gid: int) -> None:
        self._shared_gid = shared_gid
