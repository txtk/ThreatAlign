import json
from typing import Any, Dict, List

from sklearn.metrics import precision_recall_fscore_support


def load_name_id_map(path: str, allowed_types: List[str] = None) -> Dict[str, List[str]]:
    """
    Load target attributes and build a Name -> List[ID] mapping.
    Optionally filter by entity type to handle name duplicates across types.
    """
    print(f"Loading target attributes from {path}...")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error loading {path}: {e}")
        return {}

    name_map = {}
    for eid, info in data.items():
        name = info.get("name", "")
        if not name:
            continue

        if allowed_types:
            etype = info.get("entity_type", "")
            # Check if entity type matches any allowed type
            if etype not in allowed_types:
                continue

        # Store name as is (case sensitive matching per current request assumption)
        # Assuming log file candidates match these names exactly.
        if name not in name_map:
            name_map[name] = []
        name_map[name].append(str(eid))

    print(f"Loaded {len(data)} entities, {len(name_map)} unique names (filtered by types: {allowed_types}).")
    return name_map


def eval_f1(data: Dict[str, Any], target_attr_path: str):
    """
    Calculate Macro-Precision, Macro-Recall, Macro-F1, Weighted-F1
    for 'intrusion-set' entities using sklearn (Single-Label Multiclass).
    Includes branches for alignment_label:
    1. Original: Ignores alignment_label.
    2. Filter Yes: Only includes samples where top candidate alignment_label is NOT 'no'.
    3. Strict: If top candidate alignment_label is 'no', treats it as a prediction error.
    """
    target_type = "intrusion-set"
    # Filter mapping to only relevant types to avoid name collisions with irrelevant types (e.g. Malware with same name)
    name_to_ids = load_name_id_map(target_attr_path, allowed_types=[target_type, "ThreatActor"])

    # Scenario 1: Original
    y_true_orig, y_pred_orig = [], []
    # Scenario 2: Filtered (Only yes / missing)
    y_true_yes, y_pred_yes = [], []
    # Scenario 3: Strict (No is error)
    y_true_strict, y_pred_strict = [], []

    for key, item in data.items():
        entity_type = item.get("entity_type", "")
        # Filter only for specified entity type in query
        if entity_type != target_type:
            continue

        # Ground Truth IDs
        gt_ids = item.get("groud_truth", [])
        if not gt_ids:
            gt_ids = item.get("ground_truth", [])

        # User guarantees single ground truth
        if gt_ids:
            gt_id = str(gt_ids[0])
        else:
            # Skip samples without GT.
            continue

        # Identify Prediction at Rank 1
        candidates = item.get("candidates", [])
        top_candidate = candidates[0] if candidates else {}
        top_candidate_name = top_candidate.get("entity_name")
        alignment_label = top_candidate.get("alignment_label")

        pred_id = "__NO_PREDICTION__"
        if top_candidate_name:
            # Lookup ID
            ids = name_to_ids.get(top_candidate_name)
            if ids:
                pred_id = ids[0]

        # Branch 1: Original
        y_true_orig.append(gt_id)
        y_pred_orig.append(pred_id)

        # Branch 2: Filter Yes (ignore if label is 'no')
        if alignment_label != "no":
            y_true_yes.append(gt_id)
            y_pred_yes.append(pred_id)

        # Branch 3: Strict (if label is 'no', treat as wrong)
        y_true_strict.append(gt_id)
        if alignment_label == "no":
            y_pred_strict.append("__WRONG_ALIGNMENT__")
        else:
            y_pred_strict.append(pred_id)

    def _get_metrics(y_true, y_pred, desc):
        if not y_true:
            print(f"No samples found for {desc}")
            return None
        p_m, r_m, f1_m, _ = precision_recall_fscore_support(y_true, y_pred, average="macro", zero_division=0)
        p_w, r_w, f1_w, _ = precision_recall_fscore_support(y_true, y_pred, average="weighted", zero_division=0)
        print(f"\nMetrics for {desc}:")
        print(f"Macro Precision: {p_m:.4f}, Recall: {r_m:.4f}, F1: {f1_m:.4f}")
        print(f"Weighted F1: {f1_w:.4f}")
        return {"macro_precision": p_m, "macro_recall": r_m, "macro_f1": f1_m, "weighted_f1": f1_w}

    res_orig = _get_metrics(y_true_orig, y_pred_orig, f"{target_type} (Original)")
    _get_metrics(y_true_yes, y_pred_yes, f"{target_type} (Filter Yes)")
    _get_metrics(y_true_strict, y_pred_strict, f"{target_type} (Strict)")

    return res_orig
