from logging import error
from pathlib import Path
from typing import Optional
from os import readlink, symlink, remove, chmod, chown
from os.path import exists, islink

# Check if the file exists or the content is equal to content. If is not equal 
# write the content to the file


def create_symlink_if_not_present(src: Path, dst: Path, target_is_directory: bool):
    if islink(dst):
        if str(readlink(dst)) != str(src):
            remove(dst)
        else:
            return

    symlink(src, dst, target_is_directory=target_is_directory)
