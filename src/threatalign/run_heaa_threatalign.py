from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import json
import platform
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from statistics import mean, pstdev, pvariance
from typing import Any

import numpy as np
from loguru import logger


DATASETS = ("heaa_random", "heaa_time")
GRAPH_TYPES = ("source", "target")
LOWER_LAYERS = ("layer3", "layer4")
INTRUSION_LAYER = ("layer5",)
RUN_GROUP = "threatalign_heaa"
LAYER_TEMPLATE_DATASET = "heaa_random"

settings = None
JsonUtils = None
PathUtils = None
ElasticsearchVectorManager = None
pre_process = None
profile = None
match = None
run_evaluation = None
malware_mappings = None
attck_mappings = None
group_mappings = None


def run_static_preflight(dataset: str, profile_name: str, sample_size: int, output_root: Path) -> dict[str, Any]:
    from threatalign.validate_heaa_threatalign_small_batch import audit_dataset

    preflight_root = output_root / "preflight_audit"
    report = audit_dataset(dataset, profile_name, sample_size, preflight_root)
    if report.get("status") != "pass":
        raise RuntimeError(f"Static preflight audit failed; see {preflight_root / 'summary.json'}")
    return {
        "status": report.get("status"),
        "problem_count": len(report.get("problems", [])),
        "summary_path": preflight_root / "summary.json",
    }


def load_project_modules() -> None:
    global JsonUtils
    global PathUtils
    global ElasticsearchVectorManager
    global attck_mappings
    global group_mappings
    global malware_mappings
    global match
    global pre_process
    global profile
    global run_evaluation
    global settings

    if settings is not None:
        return

    from threatalign.eval.run_eval import run_evaluation as _run_evaluation
    from threatalign.match.match import match as _match
    from threatalign.prepare.prepare import pre_process as _pre_process
    from threatalign.profile.get_profile import profile as _profile
    from config import settings as _settings
    from config.mappings import rag_attck as _attck_mappings
    from config.mappings import rag_group as _group_mappings
    from config.mappings import rag_malware as _malware_mappings
    from utils.file.json_utils import JsonUtils as _JsonUtils
    from utils.file.path_utils import PathUtils as _PathUtils
    from utils.vector.vector_manager import ElasticsearchVectorManager as _ElasticsearchVectorManager

    JsonUtils = _JsonUtils
    PathUtils = _PathUtils
    ElasticsearchVectorManager = _ElasticsearchVectorManager
    attck_mappings = _attck_mappings
    group_mappings = _group_mappings
    malware_mappings = _malware_mappings
    match = _match
    pre_process = _pre_process
    profile = _profile
    run_evaluation = _run_evaluation
    settings = _settings


def _json_default(value):
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (np.floating, np.integer)):
        return value.item()
    raise TypeError(f"Cannot serialize {type(value)!r}")


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=_json_default) + "\n", encoding="utf-8")


def write_summary_csv(path: Path, dataset: str, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["dataset", "mode", "metric", "runs", "mean", "variance", "std"])
        writer.writeheader()
        for mode, mode_data in summary.items():
            for metric, values in mode_data["metrics"].items():
                writer.writerow(
                    {
                        "dataset": dataset,
                        "mode": mode,
                        "metric": metric,
                        "runs": mode_data["runs"],
                        "mean": values["mean"],
                        "variance": values["variance"],
                        "std": values["std"],
                    }
                )


def command_output(command: list[str]) -> str | None:
    try:
        return subprocess.run(command, check=True, capture_output=True, text=True).stdout.strip()
    except Exception:
        return None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_manifest(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"path": str(path), "exists": False}
    if path.is_file():
        return {
            "path": str(path),
            "exists": True,
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }

    digest = hashlib.sha256()
    count = 0
    total_bytes = 0
    for file_path in sorted(p for p in path.rglob("*") if p.is_file()):
        rel = file_path.relative_to(path).as_posix()
        size = file_path.stat().st_size
        digest.update(rel.encode())
        digest.update(b"\0")
        digest.update(str(size).encode())
        digest.update(b"\n")
        count += 1
        total_bytes += size
    return {
        "path": str(path),
        "exists": True,
        "file_count": count,
        "total_bytes": total_bytes,
        "manifest_sha256": digest.hexdigest(),
    }


def copy_snapshot(source: Path, target: Path) -> dict[str, Any]:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    return file_manifest(target)


def snapshot_dataset_inputs(dataset: str, output_dir: Path) -> dict[str, Any]:
    root = traditional_dir(dataset)
    json_dir = Path(settings.json_dir)
    sources = {
        "target_source_labels": root / "target_source_labels.json",
        "source_attributes": root / "source_attributes.json",
        "target_attributes": root / "target_attributes.json",
        "source_entity_type_id": root / "source_entity_type_id.json",
        "target_entity_type_id": root / "target_entity_type_id.json",
        "source_tuples": root / "source_tuples.txt",
        "target_tuples": root / "target_tuples.txt",
        "layer": json_dir / f"layer_{dataset}.json",
        "neo4j_static": json_dir / f"neo4j_static_{dataset}.json",
    }
    for graph_type in GRAPH_TYPES:
        vector_path = root / f"{graph_type}_vectors.pkl"
        if vector_path.exists():
            sources[f"{graph_type}_vectors"] = vector_path
    manifests = {}
    for name, source in sources.items():
        manifests[name] = copy_snapshot(source, output_dir / source.name)
    save_json(output_dir / "manifest.json", manifests)
    return manifests


def safe_name(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]+", "_", value).strip("_")


def build_rag_managers():
    return (
        ElasticsearchVectorManager(index_name="rag_malware", mappings=malware_mappings),
        ElasticsearchVectorManager(index_name="rag_attck", mappings=attck_mappings),
        ElasticsearchVectorManager(index_name="rag_group", mappings=group_mappings),
    )


def dataset_dir(dataset: str) -> Path:
    return Path(PathUtils.path_concat(settings.dataset_dir, dataset))


def traditional_dir(dataset: str) -> Path:
    return dataset_dir(dataset) / "traditional_save"


def required_graph_files(dataset: str, include_vectors: bool = True) -> list[Path]:
    root = traditional_dir(dataset)
    files = [root / "target_source_labels.json"]
    for graph_type in GRAPH_TYPES:
        files.extend(
            [
                root / f"{graph_type}_attributes.json",
                root / f"{graph_type}_entity_type_id.json",
                root / f"{graph_type}_tuples.txt",
            ]
        )
        if include_vectors:
            files.append(root / f"{graph_type}_vectors.pkl")
    return files


def validate_dataset(dataset: str, include_vectors: bool = True) -> None:
    missing = [str(path) for path in required_graph_files(dataset, include_vectors=include_vectors) if not path.exists()]
    if missing:
        raise FileNotFoundError(f"Missing required ThreatAlign inputs for {dataset}: {missing}")


def ensure_layer_files(dataset: str) -> dict[str, Any]:
    json_dir = Path(settings.json_dir)
    template_path = json_dir / f"layer_{LAYER_TEMPLATE_DATASET}.json"
    layer_path = json_dir / f"layer_{dataset}.json"
    static_path = json_dir / f"neo4j_static_{dataset}.json"

    template = JsonUtils(template_path).data
    if not template:
        raise FileNotFoundError(f"Missing layer template: {template_path}")

    changed = {"layer_created": False, "static_created": False, "static_layer_list_added": False}
    if not layer_path.exists():
        save_json(layer_path, template)
        changed["layer_created"] = True

    static = JsonUtils(static_path).data
    if not static:
        static = {"source": {}, "target": {}}
        changed["static_created"] = True
    if "layer_list" not in static:
        static["layer_list"] = [key for key in template.keys() if key.startswith("layer")]
        changed["static_layer_list_added"] = True
    static.setdefault("source", {})
    static.setdefault("target", {})
    save_json(static_path, static)
    return {
        **changed,
        "layer_path": layer_path,
        "static_path": static_path,
        "layer_manifest": file_manifest(layer_path),
        "static_manifest": file_manifest(static_path),
    }


def preprocess_dataset(dataset: str, force: bool) -> None:
    rag_malware, rag_attck, rag_group = build_rag_managers()
    root = traditional_dir(dataset)
    for graph_type in GRAPH_TYPES:
        logger.info("pre_process dataset={} graph_type={} force={}", dataset, graph_type, force)
        pre_process(dataset, str(root), graph_type, rag_malware, rag_attck, rag_group, force=force)


def profile_counts(dataset: str, profile_name: str) -> dict[str, dict[str, int]]:
    root = traditional_dir(dataset)
    output: dict[str, dict[str, int]] = {}
    for graph_type in GRAPH_TYPES:
        attrs = JsonUtils(root / f"{graph_type}_attributes.json").data
        ids = JsonUtils(root / f"{graph_type}_entity_type_id.json").data
        output[graph_type] = {}
        for entity_type in ("attack-pattern", "malware", "intrusion-set"):
            entity_ids = ids.get(entity_type, [])
            output[graph_type][entity_type] = sum(1 for entity_id in entity_ids if profile_name in attrs.get(str(entity_id), {}))
    return output


def hsage_counts(dataset: str) -> dict[str, int]:
    root = traditional_dir(dataset)
    output = {}
    for graph_type in GRAPH_TYPES:
        attrs = JsonUtils(root / f"{graph_type}_attributes.json").data
        output[graph_type] = sum(1 for value in attrs.values() if "hsage" in value)
    return output


def snapshot_profiles(dataset: str, profile_name: str, layers: tuple[str, ...], output_path: Path) -> dict[str, Any]:
    layer_to_types = {
        "layer3": ("attack-pattern",),
        "layer4": ("malware",),
        "layer5": ("intrusion-set",),
    }
    wanted_types = {entity_type for layer in layers for entity_type in layer_to_types[layer]}
    root = traditional_dir(dataset)
    snapshot = {"dataset": dataset, "profile_name": profile_name, "layers": list(layers), "graphs": {}}
    for graph_type in GRAPH_TYPES:
        attrs = JsonUtils(root / f"{graph_type}_attributes.json").data
        ids = JsonUtils(root / f"{graph_type}_entity_type_id.json").data
        graph_snapshot = {}
        for entity_type in sorted(wanted_types):
            graph_snapshot[entity_type] = {}
            for entity_id in ids.get(entity_type, []):
                entity = attrs.get(str(entity_id), {})
                graph_snapshot[entity_type][str(entity_id)] = {
                    "name": entity.get("name"),
                    "entity_type": entity.get("entity_type"),
                    "unique_id": entity.get("unique_id"),
                    profile_name: entity.get(profile_name),
                }
        snapshot["graphs"][graph_type] = graph_snapshot
    save_json(output_path, snapshot)
    return file_manifest(output_path)


def require_profiles(
    dataset: str,
    profile_name: str,
    layers: tuple[str, ...],
    max_entities_per_layer: int | None = None,
) -> None:
    layer_to_types = {
        "layer3": ("attack-pattern",),
        "layer4": ("malware",),
        "layer5": ("intrusion-set",),
    }
    root = traditional_dir(dataset)
    missing = []
    for graph_type in GRAPH_TYPES:
        attrs = JsonUtils(root / f"{graph_type}_attributes.json").data
        ids = JsonUtils(root / f"{graph_type}_entity_type_id.json").data
        for layer in layers:
            for entity_type in layer_to_types[layer]:
                entity_ids = list(ids.get(entity_type, []))
                if max_entities_per_layer is not None:
                    entity_ids = entity_ids[:max_entities_per_layer]
                for entity_id in entity_ids:
                    if profile_name not in attrs.get(str(entity_id), {}):
                        missing.append(f"{graph_type}:{entity_type}:{entity_id}")
                        if len(missing) >= 10:
                            break
                if len(missing) >= 10:
                    break
            if len(missing) >= 10:
                break
        if len(missing) >= 10:
            break
    if missing:
        raise RuntimeError(f"Missing required profiles for {dataset}/{profile_name}: {missing[:10]}")


def make_match_label_sample(
    dataset: str,
    output_path: Path,
    sample_size: int | None,
    intrusion_set_only: bool,
    profile_name: str,
    source_target_input_path: Path | None = None,
) -> Path:
    root = traditional_dir(dataset)
    source_target_path = source_target_input_path or (root / "target_source_labels.json")
    if sample_size is None:
        return source_target_path

    labels = JsonUtils(source_target_path).data
    source_attrs = JsonUtils(root / "source_attributes.json").data
    target_attrs = JsonUtils(root / "target_attributes.json").data
    allowed_types = {"intrusion-set"} if intrusion_set_only else {"intrusion-set", "malware", "attack-pattern"}
    sampled = {}
    for source_id, target_ids in labels.items():
        source_entity = source_attrs.get(str(source_id), {})
        entity_type = source_entity.get("entity_type")
        if entity_type not in allowed_types:
            continue
        if profile_name not in source_entity:
            continue
        if not target_ids:
            continue
        if any(profile_name not in target_attrs.get(str(target_id), {}) for target_id in target_ids):
            continue
        sampled[source_id] = target_ids
        if len(sampled) >= sample_size:
            break

    if not sampled:
        raise RuntimeError(f"No match labels sampled for dataset={dataset}, intrusion_set_only={intrusion_set_only}")
    save_json(output_path, sampled)
    return output_path


def generate_profiles(
    dataset: str,
    profile_name: str,
    top_n: int,
    recreate: bool,
    layers: tuple[str, ...],
    max_entities_per_layer: int | None,
    clear_existing_profiles: bool,
    is_profile: bool = True,
    is_enhance_mes: bool = False,
    is_retriver: bool = True,
    is_hsage: bool = True,
    completion_cache_dir: Path | None = None,
    graph_types: tuple[str, ...] = GRAPH_TYPES,
) -> None:
    rag_malware, rag_attck, rag_group = build_rag_managers()
    root = traditional_dir(dataset)
    last_items = JsonUtils(Path(settings.json_dir) / f"layer_{dataset}.json").get_value("all")
    logger.info(
        "generate_profiles dataset={} layers={} recreate={} max_entities_per_layer={} "
        "is_profile={} is_retriver={} is_hsage={} graph_types={}",
        dataset,
        layers,
        recreate,
        max_entities_per_layer,
        is_profile,
        is_retriver,
        is_hsage,
        graph_types,
    )
    profile(
        dataset,
        target_tuple_path=root / "target_tuples.txt",
        source_tuple_path=root / "source_tuples.txt",
        target_attribute_path=root / "target_attributes.json",
        source_attribute_path=root / "source_attributes.json",
        target_id_dict_path=root / "target_entity_type_id.json",
        source_id_dict_path=root / "source_entity_type_id.json",
        target_vector_path=root / "target_vectors.pkl",
        source_vector_path=root / "source_vectors.pkl",
        rag_malware=rag_malware,
        rag_attck=rag_attck,
        rag_group=rag_group,
        last_items=last_items,
        top_n=top_n,
        recreate=recreate,
        is_profile=is_profile,
        is_enhance_mes=is_enhance_mes,
        is_retriver=is_retriver,
        is_hsage=is_hsage,
        profile_name=profile_name,
        layers=layers,
        max_entities_per_layer=max_entities_per_layer,
        clear_existing_profiles=clear_existing_profiles,
        completion_cache_dir=completion_cache_dir,
        graph_types=graph_types,
    )


def run_match_and_eval(
    dataset: str,
    run_id: str,
    run_index: int,
    run_dir: Path,
    profile_name: str,
    top_k: int,
    is_ioc: bool,
    is_hybrid: bool,
    intrusion_set_only_match: bool,
    match_sample_size: int | None,
    source_target_input_path: Path | None,
    alignment_eval: bool,
) -> dict[str, Any]:
    root = traditional_dir(dataset)
    index_name = f"alignment_{safe_name(dataset)}_{safe_name(run_id)}_run_{run_index:02d}"
    results_path = run_dir / "alignment_results.json"
    source_vector_path = run_dir / f"source_{profile_name}_vectors.pkl"
    source_target_path = make_match_label_sample(
        dataset,
        run_dir / "target_source_labels_sample.json",
        match_sample_size,
        intrusion_set_only_match,
        profile_name,
        source_target_input_path=source_target_input_path,
    )

    started = time.time()
    match_result_path = match(
        dataset,
        source_target_path=source_target_path,
        target_attribute_path=root / "target_attributes.json",
        source_attribute_path=root / "source_attributes.json",
        source_tuple_path=root / "source_tuples.txt",
        profile_name=profile_name,
        is_ioc_mode=is_ioc,
        is_hybrid_mode=is_hybrid,
        intrusio_set_mode=intrusion_set_only_match,
        top_k=top_k,
        recreate=True,
        results_path=results_path,
        index_name=index_name,
        source_vector_path=source_vector_path,
        completion_cache_path=run_dir / "completion_cache_match_rerank.json",
    )
    alignment_metrics_path = None
    if alignment_eval:
        from threatalign.eval.eval_alignment_detailed import evaluate_alignment_results

        with open(match_result_path, "r", encoding="utf-8") as handle:
            alignment_data = json.load(handle)
        alignment_report = evaluate_alignment_results(alignment_data, rank_key="ground_truth_rank_new")
        alignment_metrics_path = run_dir / "alignment_metrics_detailed.json"
        save_json(alignment_metrics_path, alignment_report)
        metrics = alignment_report["flat_metrics"]
    else:
        metrics = run_evaluation(
            match_result_path,
            ground_truth_rank_key="ground_truth_rank_new",
            target_attr_path=root / "target_attributes.json",
            print_hit=True,
            print_f1=True,
        )
    duration = time.time() - started
    return {
        "run": run_index,
        "duration_seconds": duration,
        "index_name": index_name,
        "results_path": results_path,
        "source_target_path": source_target_path,
        "source_vector_path": source_vector_path,
        "metrics": metrics,
        "alignment_metrics_path": alignment_metrics_path,
        "result_manifest": file_manifest(results_path),
        "source_vector_manifest": file_manifest(source_vector_path),
    }


def summarize_runs(records: list[dict[str, Any]], mode_name: str) -> dict[str, Any]:
    metric_names = sorted({metric for record in records for metric in record["metrics"]})
    metrics = {}
    for metric in metric_names:
        values = [float(record["metrics"][metric]) for record in records if metric in record["metrics"]]
        metrics[metric] = {
            "values": values,
            "mean": mean(values),
            "variance": pvariance(values),
            "std": pstdev(values),
        }
    return {mode_name: {"runs": len(records), "metrics": metrics}}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run ThreatAlign attribution experiments on prepared attribution datasets.")
    parser.add_argument("--dataset", choices=DATASETS, default="heaa_random")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--profile-name", default="profile_without_enhance_5")
    parser.add_argument("--top-n", type=int, default=5)
    parser.add_argument("--top-k", type=int, default=10)
    parser.add_argument("--max-profile-entities-per-layer", type=int, default=None)
    parser.add_argument("--match-sample-size", type=int, default=None)
    parser.add_argument("--source-target-labels", default=None)
    parser.add_argument("--alignment-eval", action="store_true")
    parser.add_argument("--preflight-sample-size", type=int, default=5)
    parser.add_argument("--skip-preflight-audit", action="store_true")
    parser.add_argument("--allow-completion", action="store_true")
    parser.add_argument("--skip-prepare", action="store_true")
    parser.add_argument("--force-prepare", action="store_true")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--skip-lower-profiles", action="store_true")
    parser.add_argument("--recreate-lower-profiles", action="store_true")
    parser.add_argument("--lower-only", action="store_true")
    parser.add_argument("--reuse-intrusion-profiles", action="store_true")
    parser.add_argument(
        "--reuse-target-intrusion-profiles",
        action="store_true",
        help=(
            "Regenerate only source layer5 profiles in each run and reuse existing target "
            "layer5 profiles. Useful for report-level source-query views."
        ),
    )
    parser.add_argument("--intrusion-set-only-match", action="store_true")
    parser.add_argument("--no-ioc", action="store_true")
    parser.add_argument("--no-hybrid", action="store_true")
    parser.add_argument("--resume", action="store_true")
    return parser.parse_args()


async def main() -> None:
    args = parse_args()
    if args.runs <= 0 and not (args.prepare_only or args.lower_only):
        raise ValueError("--runs must be positive unless --prepare-only or --lower-only is used")

    needs_completion = not args.prepare_only
    if needs_completion and not args.allow_completion:
        raise SystemExit(
            "This runner will enqueue task.completion jobs for profile generation and/or matching. "
            "Pass --allow-completion after auditing queues and starting the Celery worker."
        )

    load_project_modules()
    validate_dataset(args.dataset, include_vectors=args.skip_prepare)
    run_id = args.run_id or datetime.now().astimezone().strftime("%Y%m%d_%H%M%S_threatalign_heaa")
    output_root = Path(settings.result_log_dir) / RUN_GROUP / run_id
    output_root.mkdir(parents=True, exist_ok=args.resume)

    logger.remove()
    logger.add(sys.stderr, level="INFO")
    logger.add(output_root / "runner.log", level="DEBUG", enqueue=True)

    mode_name = (
        f"ioc={not args.no_ioc},hybrid={not args.no_hybrid},profile={args.profile_name},"
        f"top_k={args.top_k},intrusion_set_only={args.intrusion_set_only_match},"
        f"alignment_eval={args.alignment_eval}"
    )

    metadata = {
        "created_at": datetime.now().astimezone().isoformat(),
        "command": sys.argv,
        "config": vars(args) | {"run_id": run_id, "output_root": output_root},
        "mode": mode_name,
        "python": sys.version,
        "platform": platform.platform(),
        "git_commit": command_output(["git", "rev-parse", "HEAD"]),
        "git_status": command_output(["git", "status", "--short"]),
        "dataset_manifests": {
            str(path): file_manifest(path) for path in required_graph_files(args.dataset, include_vectors=args.skip_prepare)
        },
    }
    save_json(output_root / "metadata.json", metadata)

    source_target_input_path = Path(args.source_target_labels) if args.source_target_labels else None
    if source_target_input_path is not None and not source_target_input_path.is_file():
        raise FileNotFoundError(f"--source-target-labels does not exist: {source_target_input_path}")
    if source_target_input_path is not None:
        save_json(
            output_root / "source_target_label_status.json",
            {"path": source_target_input_path, "manifest": file_manifest(source_target_input_path)},
        )

    layer_report = ensure_layer_files(args.dataset)
    save_json(output_root / "layer_setup.json", layer_report)
    snapshot_dataset_inputs(args.dataset, output_root / "input_snapshot_initial")
    if not args.skip_preflight_audit:
        preflight_summary = output_root / "preflight_audit" / "summary.json"
        if args.resume and preflight_summary.exists():
            report = JsonUtils(preflight_summary).data
            if report.get("status") != "pass":
                raise RuntimeError(f"Existing static preflight audit failed; see {preflight_summary}")
            preflight_report = {
                "status": report.get("status"),
                "problem_count": len(report.get("problems", [])),
                "summary_path": preflight_summary,
                "resumed": True,
            }
        else:
            preflight_report = run_static_preflight(
                args.dataset,
                args.profile_name,
                args.preflight_sample_size,
                output_root,
            )
        save_json(output_root / "preflight_status.json", preflight_report)

    if not args.skip_prepare:
        preprocess_dataset(args.dataset, force=args.force_prepare)
        save_json(output_root / "prepare_status.json", {"hsage_counts": hsage_counts(args.dataset)})

    if args.prepare_only:
        logger.info("prepare-only requested; stopping before completion-backed stages.")
        return

    if not args.skip_lower_profiles:
        generate_profiles(
            args.dataset,
            args.profile_name,
            top_n=args.top_n,
            recreate=args.recreate_lower_profiles,
            layers=LOWER_LAYERS,
            max_entities_per_layer=args.max_profile_entities_per_layer,
            clear_existing_profiles=args.recreate_lower_profiles,
            completion_cache_dir=output_root / "completion_cache" / "lower_profiles",
        )
    require_profiles(args.dataset, args.profile_name, LOWER_LAYERS, args.max_profile_entities_per_layer)
    lower_snapshot = snapshot_profiles(
        args.dataset,
        args.profile_name,
        LOWER_LAYERS,
        output_root / "lower_profile_snapshot.json",
    )
    save_json(
        output_root / "lower_profile_status.json",
        {"profile_counts": profile_counts(args.dataset, args.profile_name), "snapshot": lower_snapshot},
    )
    snapshot_dataset_inputs(args.dataset, output_root / "input_snapshot_after_lower_profiles")

    if args.lower_only:
        logger.info("lower-only requested; stopping before run loop.")
        return

    records = []
    for run_index in range(1, args.runs + 1):
        run_dir = output_root / f"run_{run_index:02d}"
        run_dir.mkdir(parents=True, exist_ok=args.resume)
        metrics_path = run_dir / "metrics.json"
        if args.resume and metrics_path.exists() and (run_dir / "alignment_results.json").exists():
            logger.info("Skipping completed ThreatAlign run {} from metrics.json", run_index)
            records.append(JsonUtils(metrics_path).data)
            continue
        run_started = time.time()
        logger.info("Starting ThreatAlign run {}/{} for dataset={}", run_index, args.runs, args.dataset)

        if args.reuse_target_intrusion_profiles:
            generate_profiles(
                args.dataset,
                args.profile_name,
                top_n=args.top_n,
                recreate=True,
                layers=INTRUSION_LAYER,
                max_entities_per_layer=args.max_profile_entities_per_layer,
                clear_existing_profiles=True,
                completion_cache_dir=run_dir / "completion_cache_profile",
                graph_types=("source",),
            )
            generate_profiles(
                args.dataset,
                args.profile_name,
                top_n=args.top_n,
                recreate=False,
                layers=INTRUSION_LAYER,
                max_entities_per_layer=args.max_profile_entities_per_layer,
                clear_existing_profiles=False,
                completion_cache_dir=run_dir / "completion_cache_profile",
                graph_types=("target",),
            )
        else:
            generate_profiles(
                args.dataset,
                args.profile_name,
                top_n=args.top_n,
                recreate=not args.reuse_intrusion_profiles,
                layers=INTRUSION_LAYER,
                max_entities_per_layer=args.max_profile_entities_per_layer,
                clear_existing_profiles=True,
                completion_cache_dir=run_dir / "completion_cache_profile",
            )
        require_profiles(args.dataset, args.profile_name, INTRUSION_LAYER, args.max_profile_entities_per_layer)
        profile_snapshot_manifest = snapshot_profiles(
            args.dataset,
            args.profile_name,
            INTRUSION_LAYER,
            run_dir / "intrusion_profile_snapshot.json",
        )
        input_snapshot_manifest = snapshot_dataset_inputs(args.dataset, run_dir / "input_snapshot_before_match")
        match_record = run_match_and_eval(
            args.dataset,
            run_id,
            run_index,
            run_dir,
            args.profile_name,
            args.top_k,
            is_ioc=not args.no_ioc,
            is_hybrid=not args.no_hybrid,
            intrusion_set_only_match=args.intrusion_set_only_match,
            match_sample_size=args.match_sample_size,
            source_target_input_path=source_target_input_path,
            alignment_eval=args.alignment_eval,
        )
        record = {
            **match_record,
            "run_total_seconds": time.time() - run_started,
            "profile_snapshot_manifest": profile_snapshot_manifest,
            "input_snapshot_manifest": input_snapshot_manifest,
            "profile_counts": profile_counts(args.dataset, args.profile_name),
        }
        records.append(record)
        save_json(run_dir / "metrics.json", record)
        logger.info("Finished run {} metrics={}", run_index, record["metrics"])

    summary = summarize_runs(records, mode_name)
    save_json(output_root / "runs.json", records)
    save_json(output_root / "summary.json", summary)
    write_summary_csv(output_root / "summary.csv", args.dataset, summary)
    print(output_root)


if __name__ == "__main__":
    asyncio.run(main())
