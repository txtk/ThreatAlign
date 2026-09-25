from __future__ import annotations

import argparse
import ast
import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


DATASETS = ("heaa_random", "heaa_time")
GRAPH_TYPES = ("source", "target")
ENTITY_TO_LAYER = {
    "attack-pattern": "layer3",
    "malware": "layer4",
    "intrusion-set": "layer5",
}
LAYER_TO_TYPES = {
    "layer3": ("attack-pattern",),
    "layer4": ("malware",),
    "layer5": ("intrusion-set",),
}
PROFILE_FIELD_RE = re.compile(r"(^profile$|profile_without|_profile$|^profile_)")
NEVER_EXPOSE_FIELDS = {
    "unique_id",
    "processed",
    "semantic",
    "hsage",
    "gid",
    "valid_from",
    "valid_until",
    "created_time",
    "modified_time",
    "group_name",
    "aka_name",
    "latitude",
    "longitude",
    "description",
    "x_mitre_description",
    "standard_attck_name",
    "standard_attck_id",
    "no_semantic_neighbors",
    "label_masked",
    "query_unit",
    "source_report",
    "source_report_id",
    "source_report_stem",
}


def repo_src_dir() -> Path:
    return Path(__file__).resolve().parents[1]


def project_root() -> Path:
    return repo_src_dir().parent


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def literal_list(node: ast.AST, known_lists: dict[str, list[str]] | None = None) -> list[str] | None:
    known_lists = known_lists or {}
    if isinstance(node, ast.Name):
        return known_lists.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = literal_list(node.left, known_lists)
        right = literal_list(node.right, known_lists)
        if left is None or right is None:
            return None
        return left + right
    if not isinstance(node, ast.List):
        return None
    values = []
    for element in node.elts:
        if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
            return None
        values.append(element.value)
    return values


def read_ignore_config(config_path: Path) -> dict[str, Any]:
    tree = ast.parse(config_path.read_text(encoding="utf-8"))
    lists: dict[str, list[str]] = {}
    ignore_dict: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name):
            values = literal_list(node.value, lists)
            if values is not None:
                lists[target.id] = values
            elif target.id == "ignore_dict" and isinstance(node.value, ast.Dict):
                for key_node, value_node in zip(node.value.keys, node.value.values):
                    if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                        if isinstance(value_node, ast.Name):
                            ignore_dict[key_node.value] = value_node.id
    return {
        "lists": lists,
        "ignore_dict": ignore_dict,
        "resolved": {dataset: lists.get(list_name, []) for dataset, list_name in ignore_dict.items()},
    }


def traditional_dir(dataset: str) -> Path:
    return project_root() / "src" / "data" / "dataset" / dataset / "traditional_save"


def json_dir() -> Path:
    return project_root() / "src" / "data" / "raw_data" / "json"


def parse_tuples(path: Path) -> tuple[dict[int, list[tuple[str, int]]], dict[int, list[tuple[str, int]]], set[int]]:
    outgoing: dict[int, list[tuple[str, int]]] = defaultdict(list)
    incoming: dict[int, list[tuple[str, int]]] = defaultdict(list)
    entities: set[int] = set()
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            parts = line.strip().split("\t")
            if len(parts) != 3:
                continue
            start, relation, end = parts
            start_id = int(start)
            end_id = int(end)
            outgoing[start_id].append((relation, end_id))
            incoming[end_id].append((relation, start_id))
            entities.add(start_id)
            entities.add(end_id)
    return outgoing, incoming, entities


def filtered_self_info(entity: dict[str, Any], ignore_list: list[str], enhance: bool = False) -> dict[str, Any]:
    output = {}
    for key, value in entity.items():
        if key in ignore_list:
            continue
        if PROFILE_FIELD_RE.search(key):
            continue
        if not enhance and "uncertain_" in key:
            continue
        output[key] = value
    return output


def sample_ids(ids_by_type: dict[str, list[Any]], sample_size: int) -> dict[str, list[str]]:
    return {
        entity_type: [str(entity_id) for entity_id in ids_by_type.get(entity_type, [])[:sample_size]]
        for entity_type in ENTITY_TO_LAYER
    }


def get_neighbour_profile_refs(
    entity_id: str,
    entity_type: str,
    attrs: dict[str, dict[str, Any]],
    outgoing: dict[int, list[tuple[str, int]]],
    incoming: dict[int, list[tuple[str, int]]],
    entities: set[int],
    last_items: list[str],
    profile_name: str,
) -> list[dict[str, Any]]:
    entity_int = int(entity_id)
    if entity_int not in entities:
        return []
    last_items_sub = last_items[: last_items.index(entity_type) + 1]
    refs = []
    edges = []
    edges.extend(("out", relation, end_id) for relation, end_id in outgoing.get(entity_int, []))
    edges.extend(("in", relation, start_id) for relation, start_id in incoming.get(entity_int, []))
    for direction, relation, neighbour_id in edges:
        neighbour = attrs.get(str(neighbour_id), {})
        neighbour_type = neighbour.get("entity_type")
        if neighbour.get("semantic") != 1 or neighbour_type not in last_items_sub:
            continue
        refs.append(
            {
                "direction": direction,
                "relation": relation,
                "neighbour_id": str(neighbour_id),
                "neighbour_name": neighbour.get("name"),
                "neighbour_type": neighbour_type,
                "has_requested_profile": profile_name in neighbour,
                "requested_profile_preview": str(neighbour.get(profile_name, ""))[:160],
                "has_any_profile_field": any(PROFILE_FIELD_RE.search(key) for key in neighbour),
                "profile_fields": sorted(key for key in neighbour if PROFILE_FIELD_RE.search(key)),
            }
        )
    return refs


def audit_dataset(dataset: str, profile_name: str, sample_size: int, output_root: Path) -> dict[str, Any]:
    config_report = read_ignore_config(project_root() / "src" / "config" / "__init__.py")
    ignore_list = config_report["resolved"].get(dataset, [])
    root = traditional_dir(dataset)
    layer_path = json_dir() / f"layer_{dataset}.json"
    if not layer_path.exists():
        layer_path = json_dir() / "layer_heaa_random.json"
    layer = load_json(layer_path)
    last_items = layer["all"]
    labels = load_json(root / "target_source_labels.json")
    target_attrs = load_json(root / "target_attributes.json")

    report: dict[str, Any] = {
        "dataset": dataset,
        "profile_name": profile_name,
        "sample_size_per_type": sample_size,
        "layer_path": str(layer_path),
        "ignore_config": {
            "ignore_dict_entry": config_report["ignore_dict"].get(dataset),
            "ignore_count": len(ignore_list),
            "ignore_list": ignore_list,
            "profile_like_mask_rule": PROFILE_FIELD_RE.pattern,
        },
        "problems": [],
        "graphs": {},
    }
    if not ignore_list:
        report["problems"].append({"severity": "error", "kind": "missing_ignore_list", "dataset": dataset})

    for graph_type in GRAPH_TYPES:
        attrs = load_json(root / f"{graph_type}_attributes.json")
        ids_by_type = load_json(root / f"{graph_type}_entity_type_id.json")
        outgoing, incoming, entities = parse_tuples(root / f"{graph_type}_tuples.txt")
        sampled = sample_ids(ids_by_type, sample_size)
        graph_report = {"sampled_ids": sampled, "samples": []}
        for entity_type, entity_ids in sampled.items():
            for entity_id in entity_ids:
                entity = attrs.get(str(entity_id), {})
                self_info = filtered_self_info(entity, ignore_list)
                exposed_keys = sorted(self_info.keys())
                leaked_profile_keys = sorted(key for key in exposed_keys if PROFILE_FIELD_RE.search(key))
                leaked_sensitive_keys = sorted(key for key in exposed_keys if key in NEVER_EXPOSE_FIELDS)
                neighbour_refs = get_neighbour_profile_refs(
                    entity_id,
                    entity_type,
                    attrs,
                    outgoing,
                    incoming,
                    entities,
                    last_items,
                    profile_name,
                )
                same_layer_profile_refs = [
                    ref
                    for ref in neighbour_refs
                    if ref["neighbour_type"] == entity_type and ref["has_requested_profile"]
                ]
                gt_name_overlap = []
                if graph_type == "source" and entity_type == "intrusion-set":
                    source_names = {str(entity.get("name", "")).lower()}
                    source_names.update(str(name).lower() for name in entity.get("aka_name", []) if name)
                    source_names.discard("")
                    for target_id in labels.get(str(entity_id), []):
                        target = target_attrs.get(str(target_id), {})
                        target_names = {str(target.get("name", "")).lower()}
                        target_names.update(str(name).lower() for name in target.get("aka_name", []) if name)
                        target_names.discard("")
                        overlap = sorted(source_names & target_names)
                        if overlap:
                            gt_name_overlap.append(
                                {
                                    "target_id": str(target_id),
                                    "target_name": target.get("name"),
                                    "overlap": overlap,
                                }
                            )
                sample_report = {
                    "entity_id": entity_id,
                    "entity_type": entity_type,
                    "name": entity.get("name"),
                    "layer": ENTITY_TO_LAYER[entity_type],
                    "raw_keys": sorted(entity.keys()),
                    "self_info_keys_after_mask": exposed_keys,
                    "self_info_preview": {key: self_info[key] for key in exposed_keys[:20]},
                    "leaked_profile_keys": leaked_profile_keys,
                    "leaked_sensitive_keys": leaked_sensitive_keys,
                    "neighbour_profile_refs": neighbour_refs,
                    "same_layer_profile_refs": same_layer_profile_refs,
                    "gt_name_overlap": gt_name_overlap,
                }
                if leaked_profile_keys:
                    report["problems"].append(
                        {
                            "severity": "error",
                            "kind": "profile_field_in_self_info",
                            "graph_type": graph_type,
                            "entity_id": entity_id,
                            "keys": leaked_profile_keys,
                        }
                    )
                if leaked_sensitive_keys:
                    report["problems"].append(
                        {
                            "severity": "error",
                            "kind": "sensitive_field_in_self_info",
                            "graph_type": graph_type,
                            "entity_id": entity_id,
                            "keys": leaked_sensitive_keys,
                        }
                    )
                path_like_values = []
                for exposed_key, exposed_value in self_info.items():
                    text_value = str(exposed_value)
                    if exposed_key.startswith("source_report") or "/source/" in text_value or text_value.startswith("source/"):
                        path_like_values.append(
                            {
                                "key": exposed_key,
                                "value_preview": text_value[:160],
                            }
                        )
                if graph_type == "source" and entity_type == "intrusion-set" and path_like_values:
                    report["problems"].append(
                        {
                            "severity": "error",
                            "kind": "source_report_metadata_visible",
                            "graph_type": graph_type,
                            "entity_id": entity_id,
                            "values": path_like_values,
                        }
                    )
                if same_layer_profile_refs:
                    report["problems"].append(
                        {
                            "severity": "warning",
                            "kind": "same_layer_requested_profile_visible",
                            "graph_type": graph_type,
                            "entity_id": entity_id,
                            "count": len(same_layer_profile_refs),
                        }
                    )
                if gt_name_overlap:
                    report["problems"].append(
                        {
                            "severity": "warning",
                            "kind": "source_name_overlaps_ground_truth_target_name",
                            "graph_type": graph_type,
                            "entity_id": entity_id,
                            "overlaps": gt_name_overlap,
                        }
                    )
                graph_report["samples"].append(sample_report)
        report["graphs"][graph_type] = graph_report

    report["status"] = "pass" if not any(p["severity"] == "error" for p in report["problems"]) else "fail"
    save_json(output_root / "summary.json", report)
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Small-batch leakage audit for HEAA ThreatAlign profile inputs.")
    parser.add_argument("--dataset", choices=DATASETS, default="heaa_random")
    parser.add_argument("--profile-name", default="profile_without_enhance_5")
    parser.add_argument("--sample-size", type=int, default=3)
    parser.add_argument("--run-id", default=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.sample_size <= 0:
        raise ValueError("--sample-size must be positive")
    run_id = args.run_id or datetime.now().astimezone().strftime("%Y%m%d_%H%M%S_small_batch_audit")
    output_root = project_root() / "src" / "data" / "log" / "test" / "threatalign_heaa_small_batch_audit" / run_id
    output_root.mkdir(parents=True, exist_ok=False)
    report = audit_dataset(args.dataset, args.profile_name, args.sample_size, output_root)
    print(json.dumps({"output_root": str(output_root), "status": report["status"], "problem_count": len(report["problems"])}, ensure_ascii=False))


if __name__ == "__main__":
    main()
