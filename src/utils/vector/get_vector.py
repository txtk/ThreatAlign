from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from utils.file.file_utils import FileUtils


def load_vector_pkl(file_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Load a pickle vector file and return its object, usually a dictionary.

    Args:
        file_path: Path to the pickle file.

    Returns:
        Dict: Dictionary that stores vectors.
    """
    return FileUtils.read_file(file_path, file_type=".pkl")


def get_vector_by_id(vector_dict: Dict[str, Any], entity_id: Union[str, int]) -> Optional[List[float]]:
    """
    Read one vector from a loaded vector dictionary by entity ID.

    Args:
        vector_dict: Dictionary loaded by load_vector_pkl.
        entity_id: Entity ID.

    Returns:
        Optional[List[float]]: The matching vector, or None if it is absent.
    """
    return vector_dict.get(str(entity_id))
