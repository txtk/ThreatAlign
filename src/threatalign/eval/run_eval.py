import json
import os
from pathlib import Path
from typing import Optional, Union

from .eval_f1 import eval_f1
from .eval_hit_and_mrr import eval_hit_and_mrr


def run_evaluation(
    file_path: Optional[Union[str, Path]],
    ground_truth_rank_key: str = "ground_truth_rank_new",
    target_attr_path: Optional[Union[str, Path]] = None,
    print_hit: bool = True,
    print_f1: bool = False,
):
    """
    Manager function to run evaluation metrics.

    Args:
        file_path: Path to the JSON log file containing prediction results.
        ground_truth_rank_key: Key in the JSON objects validation ranks (e.g. 'ground_truth_rank' or 'ground_truth_rank_new').
        target_attr_path: Path to the target attributes JSON file (required if print_f1 is True).
        print_hit: Whether to calculate and print Hit@k and MRR metrics.
        print_f1: Whether to calculate and print F1 metrics.
    """

    if not os.path.exists(file_path):
        print(f"Error: File not found at {file_path}")
        return {}

    print(f"Loading data from {file_path}...")
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error loading JSON data: {e}")
        return {}

    res = {}
    if print_hit:
        print("\n" + "=" * 30)
        print(f"Running Hit@k and MRR Evaluation (using key: {ground_truth_rank_key})")
        print("=" * 30)
        hit_metrics = eval_hit_and_mrr(data, rank_key=ground_truth_rank_key)
        res.update(hit_metrics)

    if print_f1:
        print("\n" + "=" * 30)
        print("Running F1 Evaluation")
        print("=" * 30)
        if not target_attr_path:
            # Try to infer or warn
            print("Warning: target_attr_path is required for F1 evaluation but not provided.")
            print("         Please provide the path to target_attributes.json.")
        elif not os.path.exists(target_attr_path):
            print(f"Error: Target attributes file not found at {target_attr_path}")
        else:
            f1_metrics = eval_f1(data, target_attr_path=target_attr_path)
            if f1_metrics:
                res.update(f1_metrics)

    return res


if __name__ == "__main__":
    # Example usage
    # run_evaluation(...)
    pass
