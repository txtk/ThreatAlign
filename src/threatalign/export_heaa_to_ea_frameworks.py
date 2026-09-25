from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import defaultdict
from pathlib import Path
from typing import Any


DEFAULT_FRAMEWORKS = (
    "rdgcn",
    "dual_amn",
    "fualign",
    "simple_hhea",
    "bert_int",
    "tea",
    "easyea",
)

FRAMEWORK_DIRS = {
    "rdgcn": ("RDGCN", "data"),
    "dual_amn": ("Dual-AMN", "data"),
    "fualign": ("fualign", "data"),
    "simple_hhea": ("Simple-HHEA", "data"),
    "bert_int": ("bert-int", "data"),
    "tea": ("TEA", "data"),
    "easyea": ("EasyEA-framework", "data"),
}

ATTR_IGNORE_KEYS = {
    "label_description",
    "importance",
    "semantic",
    "unique_id",
    "description",
    "gid",
    "x_mitre_description",
    "standard_attck_id",
    "standard_attck_name",
    "group_name",
    "processed",
    "hsage",
    "no_semantic_neighbors",
}


def repo_root_from_file() -> Path:
    # .../attribution/align_to_attribute/src/threatalign/export_heaa_to_ea_frameworks.py
    return Path(__file__).resolve().parents[4]


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: Any, *, ensure_ascii: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=ensure_ascii, indent=2)
        f.write("\n")


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def text_process(value: Any) -> str:
    text = "" if value is None else str(value)
    return " ".join(text.replace("_", " ").replace("/", " ").split())


def load_tsv_triples(path: Path) -> list[tuple[int, int, int]]:
    triples = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < 3:
                raise ValueError(f"Malformed triple at {path}:{line_no}: {line}")
            triples.append((int(parts[0]), int(parts[1]), int(parts[2])))
    return triples


def write_tuples(path: Path, rows: list[tuple[Any, ...]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write("\t".join(str(item) for item in row) + "\n")


def load_relation_map(path: Path) -> dict[str, int]:
    return {str(name): int(rel_id) for name, rel_id in read_json(path).items()}


def build_global_relation_map(
    source_relation_map: dict[str, int], target_relation_map: dict[str, int]
) -> tuple[list[tuple[int, str]], dict[int, int], dict[int, int]]:
    names = sorted(set(source_relation_map) | set(target_relation_map))
    name_to_global_id = {name: idx for idx, name in enumerate(names)}
    source_old_to_global = {old_id: name_to_global_id[name] for name, old_id in source_relation_map.items()}
    target_old_to_global = {old_id: name_to_global_id[name] for name, old_id in target_relation_map.items()}
    rows = sorted((idx, name) for name, idx in name_to_global_id.items())
    return rows, source_old_to_global, target_old_to_global


def remap_triple_relations(
    triples: list[tuple[int, int, int]], relation_old_to_global: dict[int, int]
) -> list[tuple[int, int, int]]:
    remapped = []
    for head, relation, tail in triples:
        if relation not in relation_old_to_global:
            raise KeyError(f"Relation id {relation} is missing from relation map")
        remapped.append((head, relation_old_to_global[relation], tail))
    return remapped


def build_ent_rows(entity_type_id: dict[str, list[int]], attributes: dict[str, dict[str, Any]]) -> list[tuple[int, str]]:
    ids = sorted({int(eid) for id_list in entity_type_id.values() for eid in id_list})
    rows = []
    missing = []
    for eid in ids:
        attr = attributes.get(str(eid))
        if attr is None:
            missing.append(eid)
            name = ""
        else:
            name = text_process(attr.get("name", ""))
        rows.append((eid, name))
    if missing:
        raise RuntimeError(f"{len(missing)} entity ids are missing attributes, sample={missing[:10]}")
    return rows


def clean_attributes(attributes: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    cleaned: dict[str, dict[str, Any]] = {}
    for eid, attr in attributes.items():
        item = {}
        for key, value in attr.items():
            if key in ATTR_IGNORE_KEYS:
                continue
            item[key] = value
        cleaned[str(eid)] = item
    return cleaned


def build_source_type_lookup(source_entity_type_id: dict[str, list[int]]) -> dict[int, str]:
    lookup = {}
    for entity_type, ids in source_entity_type_id.items():
        for eid in ids:
            lookup[int(eid)] = entity_type
    return lookup


def normalize_label_values(values: Any) -> list[int]:
    if values is None:
        return []
    if isinstance(values, list):
        return [int(v) for v in values if v is not None]
    return [int(values)]


def split_source_labels(
    labels: dict[str, Any],
    source_type_lookup: dict[int, str],
    *,
    train_ratio: float,
    seed: int,
    eval_types: set[str] | None,
) -> tuple[list[tuple[int, int]], list[tuple[int, int]], dict[str, list[int]], dict[str, Any]]:
    by_type: dict[str, list[int]] = defaultdict(list)
    normalized: dict[int, list[int]] = {}

    for source_id_str, target_ids_raw in labels.items():
        source_id = int(source_id_str)
        source_type = source_type_lookup.get(source_id, "unknown")
        if eval_types and source_type not in eval_types:
            continue
        target_ids = list(dict.fromkeys(normalize_label_values(target_ids_raw)))
        if not target_ids:
            continue
        normalized[source_id] = target_ids
        by_type[source_type].append(source_id)

    rng = random.Random(seed)
    train_sources: set[int] = set()
    test_sources: set[int] = set()
    split_by_type: dict[str, dict[str, Any]] = {}

    for source_type, source_ids in sorted(by_type.items()):
        ids = sorted(source_ids)
        rng.shuffle(ids)
        train_size = int(len(ids) * train_ratio)
        if len(ids) > 1:
            train_size = max(1, min(train_size, len(ids) - 1))
        train_ids = sorted(ids[:train_size])
        test_ids = sorted(ids[train_size:])
        train_sources.update(train_ids)
        test_sources.update(test_ids)
        split_by_type[source_type] = {
            "source_count": len(ids),
            "train_source_count": len(train_ids),
            "test_source_count": len(test_ids),
            "train_label_count": sum(len(normalized[eid]) for eid in train_ids),
            "test_label_count": sum(len(normalized[eid]) for eid in test_ids),
            "multilabel_source_count": sum(1 for eid in ids if len(normalized[eid]) > 1),
        }

    def expand(source_ids: set[int]) -> list[tuple[int, int]]:
        rows = []
        for source_id in sorted(source_ids):
            for target_id in normalized[source_id]:
                rows.append((source_id, target_id))
        return rows

    type_id_dict = {entity_type: sorted(ids) for entity_type, ids in by_type.items()}
    manifest = {
        "seed": seed,
        "train_ratio": train_ratio,
        "source_count": len(normalized),
        "label_count": sum(len(v) for v in normalized.values()),
        "multilabel_source_count": sum(1 for v in normalized.values() if len(v) > 1),
        "by_type": split_by_type,
        "train_source_ids": sorted(train_sources),
        "test_source_ids": sorted(test_sources),
    }
    return expand(train_sources), expand(test_sources), type_id_dict, {"labels": normalized, "split": manifest}


def write_framework_dataset(
    out_dir: Path,
    *,
    ent_1: list[tuple[int, str]],
    ent_2: list[tuple[int, str]],
    rel_1: list[tuple[int, str]],
    rel_2: list[tuple[int, str]],
    source_triples: list[tuple[int, int, int]],
    target_triples: list[tuple[int, int, int]],
    attr_1: dict[str, dict[str, Any]],
    attr_2: dict[str, dict[str, Any]],
    train_pairs: list[tuple[int, int]],
    test_pairs: list[tuple[int, int]],
    type_id_dict: dict[str, list[int]],
    alignment_gt: dict[int, list[int]],
    manifest: dict[str, Any],
    include_features: bool,
    include_attrs: bool,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    write_tuples(out_dir / "ent_ids_1", ent_1)
    write_tuples(out_dir / "ent_ids_2", ent_2)
    write_tuples(out_dir / "rel_ids_1", rel_1)
    write_tuples(out_dir / "rel_ids_2", rel_2)
    write_tuples(out_dir / "triples_1", source_triples)
    write_tuples(out_dir / "triples_2", target_triples)

    write_tuples(out_dir / "train_ent_ids", train_pairs)
    write_tuples(out_dir / "test_ent_ids", test_pairs)
    write_tuples(out_dir / "sup_ent_ids", train_pairs)
    write_tuples(out_dir / "ref_ent_ids", test_pairs)
    write_tuples(out_dir / "sup_pairs", train_pairs)
    write_tuples(out_dir / "ref_pairs", test_pairs)

    if include_features:
        write_tuples(out_dir / "id_features_1", ent_1)
        write_tuples(out_dir / "id_features_2", ent_2)

    if include_attrs:
        write_json(out_dir / "attr_1", attr_1)
        write_json(out_dir / "attr_2", attr_2)

    write_json(out_dir / "type_id_dict", type_id_dict)
    write_json(out_dir / "alignment_gt.json", {str(k): v for k, v in sorted(alignment_gt.items())})
    write_json(out_dir / "split_manifest.json", manifest)


def validate_entity_space(
    ent_1: list[tuple[int, str]],
    ent_2: list[tuple[int, str]],
    source_triples: list[tuple[int, int, int]],
    target_triples: list[tuple[int, int, int]],
    train_pairs: list[tuple[int, int]],
    test_pairs: list[tuple[int, int]],
) -> dict[str, Any]:
    source_ids = {eid for eid, _ in ent_1}
    target_ids = {eid for eid, _ in ent_2}
    all_ids = source_ids | target_ids

    dangling_source = [(h, r, t) for h, r, t in source_triples if h not in source_ids or t not in source_ids][:10]
    dangling_target = [(h, r, t) for h, r, t in target_triples if h not in target_ids or t not in target_ids][:10]
    bad_pairs = [(s, t) for s, t in train_pairs + test_pairs if s not in source_ids or t not in target_ids][:10]
    if dangling_source or dangling_target or bad_pairs:
        raise RuntimeError(
            "Export validation failed: "
            f"dangling_source={dangling_source}, dangling_target={dangling_target}, bad_pairs={bad_pairs}"
        )

    return {
        "source_entities": len(source_ids),
        "target_entities": len(target_ids),
        "all_entities": len(all_ids),
        "min_entity_id": min(all_ids) if all_ids else None,
        "max_entity_id": max(all_ids) if all_ids else None,
        "contiguous_global_entity_ids": bool(all_ids) and len(all_ids) == max(all_ids) + 1,
        "source_triples": len(source_triples),
        "target_triples": len(target_triples),
        "train_pairs": len(train_pairs),
        "test_pairs": len(test_pairs),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export HEAA datasets to local entity-alignment framework formats.")
    parser.add_argument("--dataset", choices=("heaa_random", "heaa_time"), default="heaa_random")
    parser.add_argument("--label-file", default="target_source_labels_alignment_reused.json")
    parser.add_argument("--train-ratio", type=float, default=0.3)
    parser.add_argument("--seed", type=int, default=20260801)
    parser.add_argument(
        "--eval-types",
        nargs="+",
        default=("intrusion-set", "malware", "attack-pattern"),
        help="Source entity types included in alignment train/test labels.",
    )
    parser.add_argument("--frameworks", nargs="+", choices=DEFAULT_FRAMEWORKS, default=DEFAULT_FRAMEWORKS)
    parser.add_argument("--align-root", default=None)
    parser.add_argument("--dataset-root", default=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    repo_root = repo_root_from_file()
    align_root = Path(args.align_root).resolve() if args.align_root else repo_root / "align"
    dataset_root = (
        Path(args.dataset_root).resolve()
        if args.dataset_root
        else repo_root / "attribution" / "align_to_attribute" / "src" / "data" / "dataset"
    )
    traditional_dir = dataset_root / args.dataset / "traditional_save"
    if not traditional_dir.exists():
        raise FileNotFoundError(f"Cannot find dataset directory: {traditional_dir}")

    label_path = traditional_dir / args.label_file
    if not label_path.exists():
        raise FileNotFoundError(f"Cannot find label file: {label_path}")

    source_entity_type_id = read_json(traditional_dir / "source_entity_type_id.json")
    target_entity_type_id = read_json(traditional_dir / "target_entity_type_id.json")
    source_attributes = read_json(traditional_dir / "source_attributes.json")
    target_attributes = read_json(traditional_dir / "target_attributes.json")
    labels = read_json(label_path)

    ent_1 = build_ent_rows(source_entity_type_id, source_attributes)
    ent_2 = build_ent_rows(target_entity_type_id, target_attributes)
    source_relation_map = load_relation_map(traditional_dir / "source_relation_map.json")
    target_relation_map = load_relation_map(traditional_dir / "target_relation_map.json")
    rel_rows, source_relation_old_to_global, target_relation_old_to_global = build_global_relation_map(
        source_relation_map, target_relation_map
    )
    source_tuples_path = traditional_dir / "source_tuples.txt"
    target_tuples_path = traditional_dir / "target_tuples.txt"
    source_triples = load_tsv_triples(source_tuples_path)
    target_triples = load_tsv_triples(target_tuples_path)
    source_triples = remap_triple_relations(source_triples, source_relation_old_to_global)
    target_triples = remap_triple_relations(target_triples, target_relation_old_to_global)

    train_pairs, test_pairs, type_id_dict, split_data = split_source_labels(
        labels,
        build_source_type_lookup(source_entity_type_id),
        train_ratio=args.train_ratio,
        seed=args.seed,
        eval_types=set(args.eval_types) if args.eval_types else None,
    )
    validation = validate_entity_space(ent_1, ent_2, source_triples, target_triples, train_pairs, test_pairs)

    base_manifest = {
        "dataset": args.dataset,
        "source_traditional_dir": str(traditional_dir),
        "label_file": str(label_path),
        "label_file_sha256": file_sha256(label_path),
        "source_tuples_sha256": file_sha256(source_tuples_path),
        "target_tuples_sha256": file_sha256(target_tuples_path),
        "global_relation_map": {name: rel_id for rel_id, name in rel_rows},
        "eval_types": list(args.eval_types),
        "validation": validation,
        **split_data["split"],
    }
    alignment_gt = split_data["labels"]

    framework_outputs = {}
    for framework in args.frameworks:
        repo_name, data_subdir = FRAMEWORK_DIRS[framework]
        out_dir = align_root / repo_name / data_subdir / args.dataset
        write_framework_dataset(
            out_dir,
            ent_1=ent_1,
            ent_2=ent_2,
            rel_1=rel_rows,
            rel_2=rel_rows,
            source_triples=source_triples,
            target_triples=target_triples,
            attr_1=clean_attributes(source_attributes),
            attr_2=clean_attributes(target_attributes),
            train_pairs=train_pairs,
            test_pairs=test_pairs,
            type_id_dict=type_id_dict,
            alignment_gt=alignment_gt,
            manifest={**base_manifest, "framework": framework, "output_dir": str(out_dir)},
            include_features=framework in {"fualign", "simple_hhea"},
            include_attrs=framework in {"bert_int", "tea", "easyea"},
        )
        framework_outputs[framework] = str(out_dir)

    summary = {**base_manifest, "framework_outputs": framework_outputs}
    summary_path = traditional_dir / f"ea_export_{args.label_file.replace('.', '_')}_manifest.json"
    write_json(summary_path, summary)

    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
