"""JSON file helpers used by the ThreatAlign pipelines."""

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Union

import aiofiles

from utils.file.file_utils import FileUtils


class JsonUtils(FileUtils):
    """Convenience wrapper around JSON load/save and simple transformations."""

    def __init__(self, json_path: Union[str, Path] = None, load=True):
        """Create a JSON helper and optionally load data from a path."""
        super().__init__()
        self.json_path = json_path
        self.data = None
        if json_path and load:
            self.data = self.load_json(json_path)

    def get_value(self, key: str, default: Any = None) -> Any:
        """Return a value by key from the loaded JSON object."""
        if self.data is None:
            raise ValueError("No data loaded; call load_json first")
        return self.data.get(key, default)

    def set_value(self, key: str, value: Any):
        """Set a value by key in the loaded JSON object."""
        if self.data is None:
            raise ValueError("No data loaded; call load_json first")
        self.data[key] = value

    def update(self, key: str, value: dict):
        """Update a nested dictionary value by key."""
        if self.data is None:
            raise ValueError("No data loaded; call load_json first")

        if key not in self.data or not isinstance(self.data[key], dict):
            raise ValueError(f"Key '{key}' does not exist or is not a dictionary")

        self.data[key].update(value)

    def load_json(self, file_path: Union[str, Path]) -> Union[Dict, List]:
        """Load a JSON file. Missing files are treated as empty dictionaries."""
        file_path = Path(file_path)

        if not file_path.exists():
            return {}

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.data = data
            self.json_path = file_path
            return data
        except json.JSONDecodeError as e:
            raise json.JSONDecodeError(f"Invalid JSON format: {e}, path={file_path}", e.doc, e.pos)

    def save_json(self, data: Union[Dict, List] = None, file_path: Union[str, Path] = None) -> None:
        """Save JSON data, defaulting to the loaded data and path."""
        if data is None:
            data = self.data

        if file_path is None:
            file_path = self.json_path

        if data is None:
            raise ValueError("No data to save")

        if file_path is None:
            raise ValueError("No output path specified")

        self.save_file(data, file_path, ".json")

    async def save_json_async(self, data: Union[Dict, List] = None, file_path: Union[str, Path] = None) -> None:
        """Asynchronously save JSON data using an atomic replace."""
        if data is None:
            data = self.data
        if file_path is None:
            file_path = self.json_path
        if data is None:
            raise ValueError("No data to save")
        if file_path is None:
            raise ValueError("No output path specified")

        file_path = Path(file_path)
        FileUtils.ensure_dir(file_path.parent)

        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=file_path.parent, delete=False, suffix=".tmp"
            ) as tmp:
                temp_path = Path(tmp.name)

            async with aiofiles.open(temp_path, "w", encoding="utf-8") as f:
                await f.write(json.dumps(data, ensure_ascii=False, indent=2))

            os.replace(temp_path, file_path)
        finally:
            if temp_path and temp_path.exists():
                temp_path.unlink(missing_ok=True)

    def split_json(self, ratio: float, output_path: Union[str, Path] = None) -> Union[Dict, List]:
        """Save and return the first ratio of the loaded list or dictionary."""
        if self.data is None:
            raise ValueError("No data loaded; call load_json first")

        if not 0 < ratio <= 1:
            raise ValueError("ratio must be in the interval (0, 1]")

        if isinstance(self.data, list):
            split_size = int(len(self.data) * ratio)
            split_data = self.data[:split_size]
        elif isinstance(self.data, dict):
            items = list(self.data.items())
            split_size = int(len(items) * ratio)
            split_data = dict(items[:split_size])
        else:
            raise ValueError("Unsupported data type; only list and dict are supported")

        if output_path is None:
            if self.json_path:
                json_path = Path(self.json_path)
                output_path = json_path.parent / f"{json_path.stem}_split{json_path.suffix}"
            else:
                raise ValueError("No output path specified and no source path is available")

        self.save_file(split_data, output_path, ".json")
        return split_data

    def apply_to_items(self, func: Callable, *args, **kwargs) -> Union[Dict, List]:
        """Apply a callable to each item in the loaded JSON data."""
        if self.data is None:
            raise ValueError("No data loaded; call load_json first")

        if not callable(func):
            raise ValueError("The provided argument is not callable")

        if isinstance(self.data, list):
            processed_data = [func(item, *args, **kwargs) for item in self.data]
        elif isinstance(self.data, dict):
            processed_data = {key: func(value, *args, **kwargs) for key, value in self.data.items()}
        else:
            processed_data = func(self.data, *args, **kwargs)

        return processed_data

    def apply_to_keys(self, func: Callable, *args, **kwargs) -> Dict:
        """Apply a callable to dictionary keys while preserving values."""
        if self.data is None:
            raise ValueError("No data loaded; call load_json first")

        if not isinstance(self.data, dict):
            raise ValueError("This method only supports dictionary JSON data")

        if not callable(func):
            raise ValueError("The provided argument is not callable")

        processed_data = {func(key, *args, **kwargs): value for key, value in self.data.items()}
        self.data = processed_data
        return processed_data

    def get_data_info(self) -> Dict[str, Any]:
        """Return basic metadata about the loaded JSON data."""
        if self.data is None:
            return {"type": None, "size": 0, "empty": True}

        data_type = type(self.data).__name__
        if isinstance(self.data, (list, dict)):
            size = len(self.data)
        else:
            size = 1

        return {
            "type": data_type,
            "size": size,
            "empty": size == 0,
            "file_path": str(self.json_path) if self.json_path else None,
        }

    def filter_data(self, condition: Callable) -> Union[Dict, List]:
        """Filter loaded JSON data using a callable predicate."""
        if self.data is None:
            raise ValueError("No data loaded; call load_json first")

        if not callable(condition):
            raise ValueError("The filter condition must be callable")

        if isinstance(self.data, list):
            filtered_data = [item for item in self.data if condition(item)]
        elif isinstance(self.data, dict):
            filtered_data = {key: value for key, value in self.data.items() if condition(value)}
        else:
            filtered_data = self.data if condition(self.data) else None

        return filtered_data

    def get_keys(self):
        return self.data.keys() if isinstance(self.data, dict) else []

    def drop_keys(self, keys: List[str]):
        if not isinstance(self.data, dict):
            raise ValueError("Data is not a dictionary; keys cannot be removed")

        for key in keys:
            self.data.pop(key, None)

    def get_items(self):
        return self.data.items() if isinstance(self.data, dict) else []

    def get_len(self):
        if self.data is None:
            return 0
        if isinstance(self.data, (list, dict)):
            return len(self.data)
        return 1
