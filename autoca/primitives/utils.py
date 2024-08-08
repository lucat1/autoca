from pathlib import Path
from typing import Optional
from os import stat, readlink, symlink, remove, chmod
from os.path import islink
# Check if the file exists or the content is equal to content. If is not equal 
# write the content to the file
def check_write_file(file_path: Path, content: bytes, 
                     permission: Optional[int] = None):
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
        chmod(file_path, permission)

def create_symlink_if_not_present(src: Path, dst: Path, target_is_directory: bool):
    if islink(dst):
        if str(readlink(dst)) != str(src):
            remove(dst)
        else:
            return

    symlink(src, dst, target_is_directory=target_is_directory)
