from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from statistics import mean, pstdev, pvariance
from typing import Any

import numpy as np
from json_repair import repair_json
from loguru import logger

from threatalign.eval.eval_alignment_detailed import evaluate_alignment_results
from threatalign.make_adj import find_directed_links
from threatalign.profile.get_profile import prepare_data
from config import ignore_dict, settings
from config.mappings import rag_attck as attck_mappings
from config.mappings import rag_group as group_mappings
from config.mappings import rag_malware as malware_mappings
from utils.celery_task import get_completion_result_batch_cached
from utils.file.json_utils import JsonUtils
from utils.vector.vector_manager import ElasticsearchVectorManager
from utils.vector.get_vector import load_vector_pkl


DATASETS = ("heaa_random", "heaa_time")
DEFAULT_PROFILE_NAME = "profile_without_enhance_5"
RUN_GROUP = "llm_global_group_guess"


class _Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for stream in self.streams:
            stream.write(data)
            stream.flush()
        return len(data)

    def flush(self):
        for stream in self.streams:
            stream.flush()


def _json_default(value):
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (np.floating, np.integer)):
        return value.item()
    raise TypeError(f"Cannot serialize {type(value)!r}")


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=_json_default) + "\n", encoding="utf-8")


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
    return {"path": str(path), "exists": True, "size": path.stat().st_size, "sha256": sha256_file(path)}


def safe_name(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]+", "_", value).strip("_")


def build_rag_managers():
    return (
        ElasticsearchVectorManager(index_name="rag_malware", mappings=malware_mappings),
        ElasticsearchVectorManager(index_name="rag_attck", mappings=attck_mappings),
        ElasticsearchVectorManager(index_name="rag_group", mappings=group_mappings),
    )


def dataset_root(dataset: str) -> Path:
    return Path(settings.dataset_dir) / dataset / "traditional_save"


def json_dir() -> Path:
    return Path(settings.json_dir)


def summarize_records(records: list[dict[str, Any]], mode_name: str) -> dict[str, Any]:
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


def _content_cache_key(dataset: str, run_index: int, source_id: str, content: dict[str, Any]) -> str:
    payload = json.dumps(content, ensure_ascii=False, sort_keys=True)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"{dataset}:run_{run_index:02d}:{source_id}:{digest}"


def load_intrusion_samples(dataset: str, sample_size: int | None = None) -> tuple[list[str], dict[str, list[Any]]]:
    root = dataset_root(dataset)
    source_type_ids = JsonUtils(root / "source_entity_type_id.json").get_value("intrusion-set") or []
    labels = json.loads((root / "target_source_labels.json").read_text(encoding="utf-8"))
    ids = [str(entity_id) for entity_id in source_type_ids if str(entity_id) in labels]
    if sample_size is not None:
        ids = ids[:sample_size]
    return ids, labels


def load_target_group_names(dataset: str) -> tuple[list[str], dict[str, list[str]]]:
    root = dataset_root(dataset)
    target_attrs = json.loads((root / "target_attributes.json").read_text(encoding="utf-8"))
    target_type_ids = JsonUtils(root / "target_entity_type_id.json").get_value("intrusion-set") or []
    names = []
    name_to_ids: dict[str, list[str]] = {}
    for target_id in target_type_ids:
        target = target_attrs.get(str(target_id), {})
        name = str(target.get("name", "")).strip()
        if not name:
            continue
        names.append(name)
        name_to_ids.setdefault(name, []).append(str(target_id))
    names = sorted(dict.fromkeys(names))
    return names, name_to_ids


def build_source_contexts(
    dataset: str,
    source_ids: list[str],
    target_group_names: list[str],
    profile_name: str,
    top_n: int,
    top_k: int,
    with_neighbor_profile: bool,
    with_retriever: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    root = dataset_root(dataset)
    source_attrs = JsonUtils(root / "source_attributes.json")
    source_outgoing, source_incoming, source_entities = find_directed_links(root / "source_tuples.txt")
    source_vectors = load_vector_pkl(root / "source_vectors.pkl") if with_retriever else {}
    layer_path = json_dir() / f"layer_{dataset}.json"
    if not layer_path.exists():
        layer_path = json_dir() / "layer_heaa_random.json"
    last_items = JsonUtils(layer_path).get_value("all")
    if with_retriever:
        rag_malware, rag_attck, rag_group = build_rag_managers()
    else:
        rag_malware = rag_attck = rag_group = None
    ignore_list = ignore_dict.get(dataset, [])

    contexts = []
    input_records = []
    for source_id in source_ids:
        content, entity = prepare_data(
            ignore_list,
            source_id,
            source_outgoing,
            source_incoming,
            source_entities,
            source_attrs,
            source_vectors,
            last_items,
            rag_malware,
            rag_attck,
            rag_group,
            top_n,
            is_profile=with_neighbor_profile,
            is_enhance_mes=False,
            is_retriver=with_retriever,
            is_hsage=True,
            profile_name=profile_name,
        )
        context = {
            **content,
            "target_classes": target_group_names,
            "top_k": top_k,
        }
        contexts.append(context)
        input_records.append(
            {
                "source_id": source_id,
                "source_name": entity.get("name"),
                "entity_type": entity.get("entity_type"),
                "context": context,
            }
        )
    return contexts, input_records


def parse_prediction(raw: str, target_group_names: list[str], top_k: int) -> list[dict[str, Any]]:
    parsed = repair_json(raw, return_objects=True)
    if not isinstance(parsed, dict):
        return []
    raw_items = parsed.get("top_10_results")
    if raw_items is None and parsed.get("category"):
        raw_items = [{"entity_name": parsed.get("category"), "reason": ""}]
    if not isinstance(raw_items, list):
        return []

    allowed = set(target_group_names)
    candidates = []
    seen = set()
    for item in raw_items:
        if isinstance(item, str):
            name = item.strip()
            reason = ""
        elif isinstance(item, dict):
            name = str(item.get("entity_name") or item.get("name") or item.get("category") or "").strip()
            reason = str(item.get("reason") or item.get("rationale") or "")
        else:
            continue
        if name not in allowed or name in seen:
            continue
        seen.add(name)
        candidates.append({"entity_name": name, "reason": reason})
        if len(candidates) >= top_k:
            break
    return candidates


def build_results(
    source_ids: list[str],
    labels: dict[str, list[Any]],
    input_records: list[dict[str, Any]],
    raw_outputs: list[str],
    target_group_names: list[str],
    name_to_ids: dict[str, list[str]],
    top_k: int,
) -> dict[str, Any]:
    results = {}
    for source_id, input_record, raw in zip(source_ids, input_records, raw_outputs):
        candidates = parse_prediction(raw, target_group_names, top_k)
        ranks = {str(gt_id): -1 for gt_id in labels.get(str(source_id), [])}
        for rank, candidate in enumerate(candidates, start=1):
            for target_id in name_to_ids.get(candidate["entity_name"], []):
                if target_id in ranks and ranks[target_id] == -1:
                    ranks[target_id] = rank
        results[str(source_id)] = {
            "name": input_record.get("source_name"),
            "entity_type": "intrusion-set",
            "groud_truth": labels.get(str(source_id), []),
            "ground_truth_rank_new": ranks,
            "candidates": candidates,
            "raw_output": raw,
        }
    return results


def run_one(args: argparse.Namespace, run_index: int, output_root: Path) -> dict[str, Any]:
    run_dir = output_root / f"run_{run_index:02d}"
    run_dir.mkdir(parents=True, exist_ok=True)
    results_path = run_dir / "alignment_results.json"
    metrics_path = run_dir / "alignment_metrics_detailed.json"
    if args.resume and results_path.exists() and metrics_path.exists():
        metrics_report = json.loads(metrics_path.read_text(encoding="utf-8"))
        return {
            "run": run_index,
            "status": "skipped_existing",
            "metrics": metrics_report["flat_metrics"],
            "results_path": results_path,
            "metrics_path": metrics_path,
        }

    source_ids, labels = load_intrusion_samples(args.dataset, args.sample_size)
    target_group_names, name_to_ids = load_target_group_names(args.dataset)
    contexts, input_records = build_source_contexts(
        args.dataset,
        source_ids,
        target_group_names,
        args.profile_name,
        args.top_n,
        args.top_k,
        args.with_neighbor_profile,
        args.with_retriever,
    )
    save_json(run_dir / "inputs.json", input_records)
    save_json(run_dir / "target_group_names.json", target_group_names)

    if args.prepare_only:
        metrics = {
            "overall_hit1": 0.0,
            "overall_hit5": 0.0,
            "overall_hit10": 0.0,
            "overall_mrr": 0.0,
        }
        run_record = {
            "run": run_index,
            "status": "prepared_only",
            "samples": len(source_ids),
            "target_group_count": len(target_group_names),
            "inputs_path": run_dir / "inputs.json",
            "metrics": metrics,
        }
        save_json(run_dir / "metrics.json", run_record)
        return run_record

    prompt_path = Path(settings.prompt_dir) / "alignment" / "global_group_guess.poml"
    cache_path = run_dir / "completion_cache_global_group_guess.json"
    cache_keys = [_content_cache_key(args.dataset, run_index, source_id, context) for source_id, context in zip(source_ids, contexts)]
    started = time.time()
    raw_outputs = get_completion_result_batch_cached(contexts, str(prompt_path), cache_path, cache_keys=cache_keys)
    duration = time.time() - started

    results = build_results(source_ids, labels, input_records, raw_outputs, target_group_names, name_to_ids, args.top_k)
    save_json(results_path, results)
    metrics_report = evaluate_alignment_results(results, rank_key="ground_truth_rank_new")
    save_json(metrics_path, metrics_report)
    run_record = {
        "run": run_index,
        "status": "complete",
        "duration_seconds": duration,
        "samples": len(source_ids),
        "target_group_count": len(target_group_names),
        "results_path": results_path,
        "metrics_path": metrics_path,
        "metrics": metrics_report["flat_metrics"],
    }
    save_json(run_dir / "metrics.json", run_record)
    return run_record


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="LLM global group-name guessing control for ThreatAlign.")
    parser.add_argument("--dataset", choices=DATASETS, default="heaa_random")
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--sample-size", type=int, default=None)
    parser.add_argument("--profile-name", default=DEFAULT_PROFILE_NAME)
    parser.add_argument("--top-n", type=int, default=5)
    parser.add_argument("--top-k", type=int, default=10)
    parser.add_argument(
        "--with-neighbor-profile",
        action="store_true",
        help="Include lower-layer neighbor profiles. Default is name-only neighbors for leakage-control use.",
    )
    parser.add_argument(
        "--with-retriever",
        action="store_true",
        help="Include retrieved source-side context. Default is disabled for leakage-control use.",
    )
    parser.add_argument("--prepare-only", action="store_true", help="Only build and log prompt inputs; do not send LLM tasks.")
    parser.add_argument("--allow-completion", action="store_true")
    parser.add_argument("--resume", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.runs <= 0:
        raise ValueError("--runs must be positive")
    if args.sample_size is not None and args.sample_size <= 0:
        raise ValueError("--sample-size must be positive")
    if not args.allow_completion and not args.prepare_only:
        raise RuntimeError("This experiment sends task.completion jobs. Pass --allow-completion to run it.")

    run_id = args.run_id or datetime.now().astimezone().strftime("%Y%m%d_%H%M%S_global_group_guess")
    output_root = Path(settings.result_log_dir) / RUN_GROUP / run_id
    output_root.mkdir(parents=True, exist_ok=args.resume)
    console_log = (output_root / "console.log").open("a", encoding="utf-8", buffering=1)
    sys.stdout = _Tee(sys.__stdout__, console_log)
    sys.stderr = _Tee(sys.__stderr__, console_log)
    logger.remove()
    logger.add(sys.stderr, level="INFO")
    logger.add(output_root / "runner.log", level="DEBUG", enqueue=True)

    root = dataset_root(args.dataset)
    metadata = {
        "created_at": datetime.now().astimezone().isoformat(),
        "command": sys.argv,
        "config": vars(args) | {"output_root": str(output_root)},
        "python": sys.version,
        "platform": platform.platform(),
        "git_commit": command_output(["git", "rev-parse", "HEAD"]),
        "git_status": command_output(["git", "status", "--short"]),
        "manifests": {
            "source_attributes": file_manifest(root / "source_attributes.json"),
            "target_attributes": file_manifest(root / "target_attributes.json"),
            "source_entity_type_id": file_manifest(root / "source_entity_type_id.json"),
            "target_entity_type_id": file_manifest(root / "target_entity_type_id.json"),
            "target_source_labels": file_manifest(root / "target_source_labels.json"),
            "source_tuples": file_manifest(root / "source_tuples.txt"),
            "source_vectors": file_manifest(root / "source_vectors.pkl"),
            "prompt": file_manifest(Path(settings.prompt_dir) / "alignment" / "global_group_guess.poml"),
        },
    }
    save_json(output_root / "metadata.json", metadata)

    records = []
    for run_index in range(1, args.runs + 1):
        logger.info("Starting global group guess run {}/{} dataset={}", run_index, args.runs, args.dataset)
        record = run_one(args, run_index, output_root)
        records.append(record)
        logger.info("Finished run {} metrics={}", run_index, record["metrics"])

    save_json(output_root / "runs.json", records)
    mode_name = (
        f"llm_global_group_guess,dataset={args.dataset},sample_size={args.sample_size},"
        f"neighbor_profile={args.with_neighbor_profile},retriever={args.with_retriever},"
        f"profile_name={args.profile_name},top_k={args.top_k}"
    )
    summary = summarize_records(records, mode_name)
    save_json(output_root / "summary.json", summary)
    write_summary_csv(output_root / "summary.csv", args.dataset, summary)
    print(output_root)


if __name__ == "__main__":
    main()
