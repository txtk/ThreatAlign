import shutil
from pathlib import Path
from typing import Union


class PathUtils:
    @staticmethod
    def ensure_dir_exists(dir_path: Union[str, Path]) -> None:
        """Ensure that a directory exists; if not, create it."""
        path = Path(dir_path)
        path.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def path_concat(*args: Union[str, Path]) -> Path:
        """Concatenate multiple path components into a single path."""
        return Path(*args)

    @staticmethod
    def path_replace(original_path: Union[str, Path], old: str, new: str) -> Path:
        """Replace a substring in the path with a new substring."""
        return Path(str(original_path).replace(old, new))

    @staticmethod
    def move_file(src: Union[str, Path], dst: Union[str, Path]) -> None:
        PathUtils.ensure_dir_exists(Path(dst).parent)
        """Move a file from src to dst."""
        shutil.move(str(src), str(dst))

    @staticmethod
    def move_dir(src: Union[str, Path], dst: Union[str, Path]) -> None:
        PathUtils.ensure_dir_exists(Path(dst))
        """Move a directory from src to dst."""
        shutil.move(str(src), str(dst))

    @staticmethod
    def copy_file(src: Union[str, Path], dst: Union[str, Path]) -> Path:
        PathUtils.ensure_dir_exists(Path(dst).parent)
        """Copy a file from src to dst and return the destination path."""
        copied_path = shutil.copy2(str(src), str(dst))
        return Path(copied_path)

    @staticmethod
    def copy_dir(src: Union[str, Path], dst: Union[str, Path]) -> Path:
        PathUtils.ensure_dir_exists(Path(dst).parent)
        """Copy a directory from src to dst and return the destination path."""
        copied_path = shutil.copytree(str(src), str(dst), dirs_exist_ok=True)
        return Path(copied_path)

    @staticmethod
    def exist_path(path: Union[str, Path]) -> bool:
        """Check if a path exists."""
        return Path(path).exists()