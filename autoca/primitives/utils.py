from pathlib import Path
from typing import Optional, Self, Dict, Any
from os import stat, readlink, symlink, remove, chmod, chown
from os.path import islink
from pwd import getpwnam
from grp import getgrnam

from autoca.primitives.serde import Serializable, Deserializable

class File(Serializable, Deserializable):
    def __init__(self, permissions: int = None, user: str = None, group: str = None):
        self._permissions = permissions
        self._user = user
        self._group = group

    def __eq__(self, other: Self):
        return self.permissions == other.permissions and self.user == other.user and self.group == other.group

    @property
    def permissions(self) -> int:
        assert self._permissions is not None
        return self._permissions

    @property
    def user(self) -> str:
        assert self._user is not None
        return self._user

    @property
    def uid(self) -> int:
        return getpwnam(self.user).pw_uid

    @property
    def group(self) -> str:
        assert self._group is not None
        return self._group

    @property
    def gid(self) -> int:
        return getgrnam(self.group).gr_gid

    def to_dict(self) -> Dict[str, Any]:
        return {
            "permissions": self.permissions,
            "user": self.user,
            "group": self.group
        }

    def from_dict(self, dict: Dict[str, Any]):
        return self.__class__(
            permissions=dict["permissions"],
            user=dict["user"],
            group=dict["group"]
        )

# Check if the file exists or the content is equal to content. If is not equal 
# write the content to the file
def check_write_file(file_path: Path, content: bytes, 
                     permission: Optional[File] = None):
    try:
        crt = open(file_path, "rb")
        if crt.read() != content:
            crt.close()

            crt = open(file_path, "wb")
            crt.write(content)
            crt.close()
    except FileNotFoundError:
        crt = open(file_path, "wb")
        crt.write(content)
        crt.close()

    if permission is not None:
        chown(file_path, permission.uid, permission.gid)
        chmod(file_path, permission.permissions)


def create_symlink_if_not_present(src: Path, dst: Path, target_is_directory: bool):
    if islink(dst):
        if str(readlink(dst)) != str(src):
            remove(dst)
        else:
            return

    symlink(src, dst, target_is_directory=target_is_directory)
