import json
import os
import pickle
import shutil
import tempfile
from pathlib import Path
from typing import List, Union

import pandas as pd
import yaml


class FileUtils:
    """Small helpers for common file operations."""

    @staticmethod
    def ensure_dir(directory: Union[str, Path]) -> None:
        """Create a directory if it does not already exist."""
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def save_file(
        data: Union[dict, list, pd.DataFrame, str], file_path: Union[str, Path], file_type: str = None
    ) -> None:
        """Save data to disk, inferring the file type from the suffix when needed."""
        file_path = Path(file_path)
        FileUtils.ensure_dir(file_path.parent)

        if file_type is None:
            file_type = file_path.suffix.lower()

        if file_type == ".json":
            temp_path = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w", encoding="utf-8", dir=file_path.parent, delete=False, suffix=".tmp"
                ) as tmp:
                    json.dump(data, tmp, ensure_ascii=False, indent=4)
                    tmp.flush()
                    os.fsync(tmp.fileno())
                    temp_path = Path(tmp.name)

                os.replace(temp_path, file_path)
            finally:
                if temp_path and temp_path.exists():
                    temp_path.unlink(missing_ok=True)

        elif file_type == ".yaml" or file_type == ".yml":
            with open(file_path, "w", encoding="utf-8") as f:
                yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

        elif file_type == ".csv":
            if isinstance(data, pd.DataFrame):
                data.to_csv(file_path, index=False, encoding="utf-8")
            else:
                pd.DataFrame(data).to_csv(file_path, index=False, encoding="utf-8")

        elif file_type == ".txt":
            with open(file_path, "w", encoding="utf-8") as f:
                if isinstance(data, (list, tuple)):
                    f.write("\n".join(map(str, data)))
                else:
                    f.write(str(data))

        elif file_type == ".pkl":
            with open(file_path, "wb") as f:
                pickle.dump(data, f)

        else:
            raise ValueError(f"Unsupported file type: {file_type}")

    @staticmethod
    def read_file(
        file_path: Union[str, Path], file_type: str = ".txt", encoding: str = "utf-8", list_mode: bool = False
    ) -> Union[dict, list, pd.DataFrame, str]:
        """Read a JSON, YAML, CSV, pickle, or text file."""
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File does not exist: {file_path}")

        if file_type is None:
            file_type = file_path.suffix.lower()

        if file_type == ".json":
            with open(file_path, "r", encoding=encoding) as f:
                return json.load(f)

        elif file_type in (".yaml", ".yml"):
            with open(file_path, "r", encoding=encoding) as f:
                return yaml.safe_load(f)

        elif file_type == ".csv":
            return pd.read_csv(file_path, encoding=encoding)

        elif file_type == ".pkl":
            with open(file_path, "rb") as f:
                return pickle.load(f)

        elif file_type == ".txt":
            with open(file_path, "r", encoding=encoding) as f:
                if list_mode:
                    return [line.strip() for line in f.readlines()]
                return "".join(f.readlines())

        else:
            raise ValueError(f"Unsupported file type: {file_type}")

    @staticmethod
    def delete_file(file_path: Union[str, Path]) -> bool:
        """Delete a file if it exists."""
        try:
            file_path = Path(file_path)
            if file_path.exists():
                file_path.unlink()
            return True
        except Exception as e:
            print(f"Failed to delete file: {e}")
            return False

    @staticmethod
    def delete_directory(directory: Union[str, Path]) -> bool:
        """Delete a directory tree if it exists."""
        try:
            directory = Path(directory)
            if directory.exists():
                shutil.rmtree(directory)
            return True
        except Exception as e:
            print(f"Failed to delete directory: {e}")
            return False

    @staticmethod
    def list_files(directory: Union[str, Path], pattern: str = "*", recursive: bool = False) -> List[Path]:
        """List files in a directory."""
        directory = Path(directory)
        if recursive:
            return list(directory.rglob(pattern))
        return list(directory.glob(pattern))

    @staticmethod
    def list_dir(directory: Union[str, Path], pattern: str = "*", recursive: bool = False) -> List[Path]:
        """List subdirectories in a directory."""
        directory = Path(directory)
        if recursive:
            return [d for d in directory.rglob(pattern) if d.is_dir()]
        return [d for d in directory.glob(pattern) if d.is_dir()]

    @staticmethod
    def get_file_size(file_path: Union[str, Path]) -> int:
        """Return a file size in bytes."""
        return Path(file_path).stat().st_size

    @staticmethod
    def get_file_extension(file_path: Union[str, Path]) -> str:
        """Return a file suffix including the leading dot."""
        return Path(file_path).suffix.lower()

    @staticmethod
    def exist_file(file_path: Union[str, Path]) -> bool:
        """Return whether a file exists."""
        return Path(file_path).exists()
