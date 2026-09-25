from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


DATASET_DEFAULT_REFERENCES = {
    "heaa_random": {
        "malware": (),
        "attack-pattern": (),
    },
    "heaa_time": {
        "malware": (),
        "attack-pattern": (),
    },
}

DEFAULT_EVAL_TYPES = ("intrusion-set", "malware", "attack-pattern")


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _normalize(value: Any) -> str:
    text = str(value or "").strip().casefold()
    text = text.replace("–", "-").replace("—", "-")
    text = re.sub(r"\s+", " ", text)
    return text


def _clean_malware_name(value: Any) -> str:
    # Keep this intentionally close to align_judge.main._iter_malware_name_gid:
    # old malware labels are name-based, and their reuse logic treats source and
    # target names as an undirected graph.
    return _normalize(value)


def _attack_keys(entity: dict[str, Any]) -> set[str]:
    values: list[Any] = []
    for key in ("uncertain_id", "id", "external_id", "x_mitre_id", "name", "uncertain_name", "aliases"):
        value = entity.get(key)
        if isinstance(value, list):
            values.extend(value)
        elif isinstance(value, str):
            values.append(value)

    keys = {_normalize(value) for value in values if _normalize(value)}
    expanded = set(keys)
    for key in keys:
        # ATT&CK ids are the most stable keys.  Some records store "T1566:
        # Phishing" or similar textual variants; recover the id when present.
        for match in re.finditer(r"\bt\d{4}(?:\.\d{3})?\b", key):
            expanded.add(match.group(0))
    return expanded


def _entity_keys(entity: dict[str, Any], entity_type: str) -> set[str]:
    if entity_type == "malware":
        key = _clean_malware_name(entity.get("name"))
        return {key} if key else set()
    if entity_type == "attack-pattern":
        return _attack_keys(entity)
    raise ValueError(f"Unsupported reusable label type: {entity_type}")


def _iter_entities(attrs: dict[str, dict[str, Any]], entity_type: str):
    for gid, entity in attrs.items():
        if isinstance(entity, dict) and entity.get("entity_type") == entity_type:
            yield str(gid), entity


def _connected_component(graph: dict[str, set[str]], start_keys: set[str]) -> set[str]:
    stack = [key for key in start_keys if key in graph]
    seen: set[str] = set()
    while stack:
        key = stack.pop()
        if key in seen:
            continue
        seen.add(key)
        stack.extend(graph.get(key, set()) - seen)
    return seen


def _build_reference_graph(
    dataset_root: Path,
    reference_datasets: tuple[str, ...],
    entity_type: str,
) -> tuple[dict[str, set[str]], dict[str, int]]:
    graph: dict[str, set[str]] = defaultdict(set)
    provenance_counts: dict[str, int] = {}

    for reference in reference_datasets:
        ref_root = dataset_root / reference / "traditional_save"
        label_path = ref_root / "target_source_labels.json"
        source_attr_path = ref_root / "source_attributes.json"
        target_attr_path = ref_root / "target_attributes.json"
        if not (label_path.is_file() and source_attr_path.is_file() and target_attr_path.is_file()):
            provenance_counts[reference] = 0
            continue

        labels = _load_json(label_path)
        source_attrs = _load_json(source_attr_path)
        target_attrs = _load_json(target_attr_path)
        used = 0

        for source_id, target_ids in labels.items():
            source_entity = source_attrs.get(str(source_id), {})
            if source_entity.get("entity_type") != entity_type:
                continue
            source_keys = _entity_keys(source_entity, entity_type)
            target_keys: set[str] = set()
            for target_id in target_ids or []:
                target_entity = target_attrs.get(str(target_id), {})
                if target_entity.get("entity_type") == entity_type:
                    target_keys.update(_entity_keys(target_entity, entity_type))
            if not source_keys or not target_keys:
                continue
            used += 1
            for source_key in source_keys:
                graph[source_key].update(target_keys)
                for target_key in target_keys:
                    graph[target_key].add(source_key)

        provenance_counts[reference] = used

    return graph, provenance_counts


def _project_reused_labels(
    dataset_root: Path,
    dataset: str,
    reference_datasets: tuple[str, ...],
    entity_type: str,
) -> tuple[dict[str, list[int]], dict[str, Any]]:
    current_root = dataset_root / dataset / "traditional_save"
    source_attrs = _load_json(current_root / "source_attributes.json")
    target_attrs = _load_json(current_root / "target_attributes.json")
    graph, provenance_counts = _build_reference_graph(dataset_root, reference_datasets, entity_type)

    target_ids_by_key: dict[str, set[int]] = defaultdict(set)
    for target_id, target_entity in _iter_entities(target_attrs, entity_type):
        for key in _entity_keys(target_entity, entity_type):
            target_ids_by_key[key].add(int(target_id) if str(target_id).isdigit() else target_id)

    projected: dict[str, list[int]] = {}
    for source_id, source_entity in _iter_entities(source_attrs, entity_type):
        component = _connected_component(graph, _entity_keys(source_entity, entity_type))
        target_ids: set[int] = set()
        for key in component:
            target_ids.update(target_ids_by_key.get(key, set()))
        if target_ids:
            projected[str(source_id)] = sorted(target_ids, key=lambda value: (str(type(value)), value))

    diagnostics = {
        "entity_type": entity_type,
        "reference_datasets": list(reference_datasets),
        "reference_label_counts": provenance_counts,
        "reference_graph_keys": len(graph),
        "projected_sources": len(projected),
        "projected_multilabel_sources": sum(1 for targets in projected.values() if len(targets) > 1),
    }
    return projected, diagnostics


def build_alignment_labels(
    dataset: str,
    dataset_root: Path,
    output_path: Path,
    reference_config: dict[str, tuple[str, ...]],
    eval_types: tuple[str, ...] = DEFAULT_EVAL_TYPES,
) -> dict[str, Any]:
    current_root = dataset_root / dataset / "traditional_save"
    current_labels = _load_json(current_root / "target_source_labels.json")
    source_attrs = _load_json(current_root / "source_attributes.json")
    bundled_label_path = current_root / "target_source_labels_alignment_reused.json"
    bundled_labels = _load_json(bundled_label_path) if bundled_label_path.is_file() else {}

    output: dict[str, list[int]] = {}
    diagnostics: dict[str, Any] = {
        "created_at": datetime.now().astimezone().isoformat(),
        "dataset": dataset,
        "dataset_root": str(dataset_root),
        "source_label_path": str(current_root / "target_source_labels.json"),
        "bundled_label_path": str(bundled_label_path),
        "output_path": str(output_path),
        "eval_types": list(eval_types),
        "reused_types": {},
    }

    # Keep current intrusion-set labels.  These are dataset-specific group
    # labels, not reusable low-layer labels.
    for source_id, target_ids in current_labels.items():
        entity_type = source_attrs.get(str(source_id), {}).get("entity_type")
        if entity_type in eval_types and entity_type not in reference_config:
            output[str(source_id)] = target_ids

    for entity_type, references in reference_config.items():
        if entity_type not in eval_types:
            continue
        if references:
            projected, type_diagnostics = _project_reused_labels(dataset_root, dataset, references, entity_type)
            output.update(projected)
            diagnostics["reused_types"][entity_type] = type_diagnostics
            continue

        copied = {
            str(source_id): target_ids
            for source_id, target_ids in bundled_labels.items()
            if source_attrs.get(str(source_id), {}).get("entity_type") == entity_type
        }
        output.update(copied)
        diagnostics["reused_types"][entity_type] = {
            "entity_type": entity_type,
            "reference_datasets": [],
            "source": "bundled_alignment_labels",
            "copied_sources": len(copied),
            "copied_multilabel_sources": sum(1 for targets in copied.values() if len(targets) > 1),
        }

    type_counts: dict[str, int] = defaultdict(int)
    type_multilabel_counts: dict[str, int] = defaultdict(int)
    for source_id, target_ids in output.items():
        entity_type = source_attrs.get(str(source_id), {}).get("entity_type", "missing")
        type_counts[entity_type] += 1
        if isinstance(target_ids, list) and len(target_ids) > 1:
            type_multilabel_counts[entity_type] += 1

    diagnostics["output_labels"] = len(output)
    diagnostics["output_type_counts"] = dict(sorted(type_counts.items()))
    diagnostics["output_multilabel_type_counts"] = dict(sorted(type_multilabel_counts.items()))

    _save_json(output_path, output)
    _save_json(output_path.with_suffix(".diagnostics.json"), diagnostics)
    return diagnostics


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build reusable ThreatAlign alignment labels.")
    parser.add_argument("--dataset", choices=tuple(DATASET_DEFAULT_REFERENCES), required=True)
    parser.add_argument("--dataset-root", default="data/dataset")
    parser.add_argument("--output", default=None)
    parser.add_argument(
        "--eval-types",
        nargs="+",
        choices=DEFAULT_EVAL_TYPES,
        default=list(DEFAULT_EVAL_TYPES),
        help="Entity types to include in the generated label file.",
    )
    parser.add_argument("--malware-reference", action="append", default=None, help="Optional private legacy dataset(s) used to project malware labels.")
    parser.add_argument("--attack-reference", action="append", default=None, help="Optional private legacy dataset(s) used to project attack-pattern labels.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    dataset_root = Path(args.dataset_root)
    default_refs = DATASET_DEFAULT_REFERENCES[args.dataset]
    reference_config = {
        "malware": tuple(args.malware_reference or default_refs["malware"]),
        "attack-pattern": tuple(args.attack_reference or default_refs["attack-pattern"]),
    }
    output_path = Path(args.output) if args.output else (
        dataset_root / args.dataset / "traditional_save" / "target_source_labels_alignment_reused.json"
    )
    diagnostics = build_alignment_labels(
        args.dataset,
        dataset_root,
        output_path,
        reference_config,
        eval_types=tuple(args.eval_types),
    )
    print(json.dumps(diagnostics, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
