from __future__ import annotations

import argparse
import asyncio
import csv
import json
import platform
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from loguru import logger

from threatalign import run_heaa_threatalign as base


RUN_GROUP = "threatalign_heaa_ablation"
TABLE_METRICS = ("macro_precision", "macro_recall", "macro_f1", "weighted_f1")
TABLE_METRIC_LABELS = {
    "macro_precision": "M-P ↑",
    "macro_recall": "M-R ↑",
    "macro_f1": "M-F1 ↑",
    "weighted_f1": "W-F1 ↑",
}


@dataclass(frozen=True)
class AblationMode:
    name: str
    label: str
    profile_name: str
    top_n: int
    is_profile: bool
    is_retriver: bool
    is_hsage: bool
    is_ioc: bool
    is_hybrid: bool

    @property
    def profile_key(self) -> str:
        return base.safe_name(
            f"{self.profile_name}_topn_{self.top_n}_profile_{self.is_profile}_"
            f"retriever_{self.is_retriver}_hsage_{self.is_hsage}"
        )


SINGLE_FACTOR_MODES = [
    AblationMode(
        name="full",
        label="Full",
        profile_name="profile_without_enhance_5",
        top_n=5,
        is_profile=True,
        is_retriver=True,
        is_hsage=True,
        is_ioc=True,
        is_hybrid=True,
    ),
    AblationMode(
        name="w_o_ioc",
        label="w/o IOC",
        profile_name="profile_without_enhance_5",
        top_n=5,
        is_profile=True,
        is_retriver=True,
        is_hsage=True,
        is_ioc=False,
        is_hybrid=True,
    ),
    AblationMode(
        name="w_o_hybrid_text",
        label="w/o Hybrid Profile Matching",
        profile_name="profile_without_enhance_5",
        top_n=5,
        is_profile=True,
        is_retriver=True,
        is_hsage=True,
        is_ioc=True,
        is_hybrid=False,
    ),
    AblationMode(
        name="w_o_retriever",
        label="w/o Retriever",
        profile_name="profile_without_enhance_5_without_retriver",
        top_n=5,
        is_profile=True,
        is_retriver=False,
        is_hsage=True,
        is_ioc=True,
        is_hybrid=True,
    ),
    AblationMode(
        name="w_o_neighbor_profile",
        label="w/o Neighbor Profile",
        profile_name="profile_without_enhance_5_without_profile",
        top_n=5,
        is_profile=False,
        is_retriver=True,
        is_hsage=True,
        is_ioc=True,
        is_hybrid=True,
    ),
    AblationMode(
        name="w_o_hsage_ranking",
        label="w/o HSAGE Ranking",
        profile_name="profile_without_enhance_5_no_hsage",
        top_n=5,
        is_profile=True,
        is_retriver=True,
        is_hsage=False,
        is_ioc=True,
        is_hybrid=True,
    ),
]


CUMULATIVE_MODES = [
    AblationMode(
        name="cum_full",
        label="Full",
        profile_name="profile_without_enhance_5",
        top_n=5,
        is_profile=True,
        is_retriver=True,
        is_hsage=True,
        is_ioc=True,
        is_hybrid=True,
    ),
    AblationMode(
        name="cum_no_hsage_ranking",
        label="- HSAGE Ranking",
        profile_name="profile_without_enhance_5_no_hsage",
        top_n=5,
        is_profile=True,
        is_retriver=True,
        is_hsage=False,
        is_ioc=True,
        is_hybrid=True,
    ),
    AblationMode(
        name="cum_no_hsage_ranking_no_neighbor_profile",
        label="- HSAGE Ranking - Neighbor Profile",
        profile_name="profile_without_enhance_5_no_hsage_no_profile",
        top_n=5,
        is_profile=False,
        is_retriver=True,
        is_hsage=False,
        is_ioc=True,
        is_hybrid=True,
    ),
    AblationMode(
        name="cum_no_hsage_ranking_no_neighbor_profile_no_retriever",
        label="- HSAGE Ranking - Neighbor Profile - Retriever",
        profile_name="profile_without_enhance_5_no_hsage_no_profile_no_retriver",
        top_n=5,
        is_profile=False,
        is_retriver=False,
        is_hsage=False,
        is_ioc=True,
        is_hybrid=True,
    ),
    AblationMode(
        name="cum_no_hsage_ranking_no_neighbor_profile_no_retriever_no_hybrid_text",
        label="- HSAGE Ranking - Neighbor Profile - Retriever - Hybrid Profile Matching",
        profile_name="profile_without_enhance_5_no_hsage_no_profile_no_retriver",
        top_n=5,
        is_profile=False,
        is_retriver=False,
        is_hsage=False,
        is_ioc=True,
        is_hybrid=False,
    ),
    AblationMode(
        name="cum_no_hsage_ranking_no_neighbor_profile_no_retriever_no_hybrid_text_no_ioc",
        label="- HSAGE Ranking - Neighbor Profile - Retriever - Hybrid Profile Matching - IOC Matching",
        profile_name="profile_without_enhance_5_no_hsage_no_profile_no_retriver",
        top_n=5,
        is_profile=False,
        is_retriver=False,
        is_hsage=False,
        is_ioc=False,
        is_hybrid=False,
    ),
]

ABLATION_MODES = SINGLE_FACTOR_MODES + CUMULATIVE_MODES
CUMULATIVE_REMAINING_MODES = CUMULATIVE_MODES[2:]


def available_mode_names() -> list[str]:
    return [mode.name for mode in ABLATION_MODES]


def select_modes(mode_arg: str) -> list[AblationMode]:
    if mode_arg == "all":
        return list(SINGLE_FACTOR_MODES)
    if mode_arg == "single":
        return list(SINGLE_FACTOR_MODES)
    if mode_arg == "cumulative":
        return list(CUMULATIVE_MODES)
    if mode_arg == "cumulative_remaining":
        return list(CUMULATIVE_REMAINING_MODES)
    wanted = [item.strip() for item in mode_arg.split(",") if item.strip()]
    by_name = {mode.name: mode for mode in ABLATION_MODES}
    unknown = [name for name in wanted if name not in by_name]
    if unknown:
        raise ValueError(f"Unknown ablation modes {unknown}; available={available_mode_names()}")
    return [by_name[name] for name in wanted]


def unique_profile_modes(modes: list[AblationMode]) -> list[AblationMode]:
    seen = set()
    output = []
    for mode in modes:
        if mode.profile_key in seen:
            continue
        seen.add(mode.profile_key)
        output.append(mode)
    return output


def mode_key(mode: AblationMode, top_k: int, intrusion_set_only: bool = False) -> str:
    return (
        f"mode={mode.name},ioc={mode.is_ioc},hybrid={mode.is_hybrid},"
        f"profile={mode.profile_name},top_n={mode.top_n},top_k={top_k},"
        f"is_profile={mode.is_profile},is_retriver={mode.is_retriver},"
        f"is_hsage={mode.is_hsage},intrusion_set_only={intrusion_set_only}"
    )


def write_ablation_table(
    path: Path,
    summary: dict[str, Any],
    modes: list[AblationMode],
    top_k: int,
    intrusion_set_only: bool,
) -> None:
    rows = []
    for mode in modes:
        key = mode_key(mode, top_k, intrusion_set_only)
        metrics = summary[key]["metrics"]
        row = {"Mode": mode.label}
        for metric in TABLE_METRICS:
            if metric in metrics:
                row[metric] = f"{metrics[metric]['mean']:.4f} ± {metrics[metric]['std']:.4f}"
            else:
                row[metric] = "N/A"
        rows.append(row)

    headers = ["Mode", *(TABLE_METRIC_LABELS[metric] for metric in TABLE_METRICS)]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append(
            "| "
            + " | ".join([row["Mode"], *(row[metric] for metric in TABLE_METRICS)])
            + " |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_flat_runs_csv(path: Path, records_by_mode: dict[str, list[dict[str, Any]]]) -> None:
    metric_names = sorted(
        {metric for records in records_by_mode.values() for record in records for metric in record["metrics"]}
    )
    fieldnames = [
        "mode",
        "run",
        "profile_name",
        "is_profile",
        "is_retriver",
        "is_hsage",
        "is_ioc",
        "is_hybrid",
        "intrusion_set_only_match",
        *metric_names,
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for mode_name, records in records_by_mode.items():
            for record in records:
                row = {
                    "mode": mode_name,
                    "run": record["run"],
                    "profile_name": record["mode_config"]["profile_name"],
                    "is_profile": record["mode_config"]["is_profile"],
                    "is_retriver": record["mode_config"]["is_retriver"],
                    "is_hsage": record["mode_config"]["is_hsage"],
                    "is_ioc": record["mode_config"]["is_ioc"],
                    "is_hybrid": record["mode_config"]["is_hybrid"],
                    "intrusion_set_only_match": record.get("intrusion_set_only_match", False),
                }
                row.update(record["metrics"])
                writer.writerow(row)


def run_profile_preflight(dataset: str, profile_name: str, sample_size: int, output_dir: Path) -> dict[str, Any]:
    from threatalign.validate_heaa_threatalign_small_batch import audit_dataset

    report = audit_dataset(dataset, profile_name, sample_size, output_dir)
    if report.get("status") != "pass":
        raise RuntimeError(f"Static preflight audit failed; see {output_dir / 'summary.json'}")
    return {
        "status": report.get("status"),
        "problem_count": len(report.get("problems", [])),
        "summary_path": output_dir / "summary.json",
    }


def restore_profiles_from_snapshot(dataset: str, snapshot_path: Path) -> dict[str, Any]:
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    profile_name = snapshot["profile_name"]
    root = base.traditional_dir(dataset)
    restored = {"profile_name": profile_name, "graphs": {}}
    for graph_type, graph_data in snapshot.get("graphs", {}).items():
        attrs = base.JsonUtils(root / f"{graph_type}_attributes.json")
        count = 0
        for entities in graph_data.values():
            for entity_id, item in entities.items():
                entity = attrs.get_value(str(entity_id), {})
                if profile_name in item:
                    entity[profile_name] = item.get(profile_name)
                    attrs.set_value(str(entity_id), entity)
                    count += 1
        attrs.save_json()
        restored["graphs"][graph_type] = count
    return restored


def load_completed_record(run_dir: Path) -> dict[str, Any] | None:
    metrics_path = run_dir / "metrics.json"
    result_path = run_dir / "alignment_results.json"
    if not metrics_path.exists() or not result_path.exists():
        return None
    return json.loads(metrics_path.read_text(encoding="utf-8"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run HEAA ThreatAlign ablation experiments with full logs.")
    parser.add_argument("--dataset", choices=base.DATASETS, default="heaa_random")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--run-id", default=None)
    parser.add_argument(
        "--modes",
        default="all",
        help=(
            "all/single for single-factor modes, cumulative for progressive removal, "
            "cumulative_remaining for progressive-removal modes after Full and "
            f"'- HSAGE Ranking', or comma list from {available_mode_names()}"
        ),
    )
    parser.add_argument("--top-k", type=int, default=10)
    parser.add_argument("--allow-completion", action="store_true")
    parser.add_argument("--skip-prepare", action="store_true")
    parser.add_argument("--force-prepare", action="store_true")
    parser.add_argument("--skip-lower-profiles", action="store_true")
    parser.add_argument("--recreate-lower-profiles", action="store_true")
    parser.add_argument("--max-profile-entities-per-layer", type=int, default=None)
    parser.add_argument("--match-sample-size", type=int, default=None)
    parser.add_argument("--intrusion-set-only-match", action="store_true")
    parser.add_argument("--preflight-sample-size", type=int, default=20)
    parser.add_argument("--skip-preflight-audit", action="store_true")
    parser.add_argument("--resume", action="store_true")
    return parser.parse_args()


async def main() -> None:
    args = parse_args()
    if args.runs <= 0:
        raise ValueError("--runs must be positive")
    if not args.allow_completion:
        raise SystemExit(
            "This ablation runner will enqueue task.completion jobs for profile generation and matching. "
            "Pass --allow-completion after auditing queues and starting the Celery worker."
        )

    modes = select_modes(args.modes)
    profile_modes = unique_profile_modes(modes)

    base.load_project_modules()
    base.validate_dataset(args.dataset)

    run_id = args.run_id or datetime.now().astimezone().strftime("%Y%m%d_%H%M%S_threatalign_heaa_ablation")
    output_root = Path(base.settings.result_log_dir) / RUN_GROUP / run_id
    output_root.mkdir(parents=True, exist_ok=args.resume)

    logger.remove()
    logger.add(sys.stderr, level="INFO")
    logger.add(output_root / "runner.log", level="DEBUG", enqueue=True)

    metadata = {
        "created_at": datetime.now().astimezone().isoformat(),
        "command": sys.argv,
        "config": vars(args) | {"run_id": run_id, "output_root": output_root},
        "modes": [asdict(mode) | {"profile_key": mode.profile_key} for mode in modes],
        "profile_modes": [asdict(mode) | {"profile_key": mode.profile_key} for mode in profile_modes],
        "python": sys.version,
        "platform": platform.platform(),
        "git_commit": base.command_output(["git", "rev-parse", "HEAD"]),
        "git_status": base.command_output(["git", "status", "--short"]),
        "dataset_manifests": {str(path): base.file_manifest(path) for path in base.required_graph_files(args.dataset)},
    }
    base.save_json(output_root / "metadata.json", metadata)

    layer_report = base.ensure_layer_files(args.dataset)
    base.save_json(output_root / "layer_setup.json", layer_report)
    base.snapshot_dataset_inputs(args.dataset, output_root / "input_snapshot_initial")

    if not args.skip_preflight_audit:
        preflight = {}
        for profile_mode in profile_modes:
            preflight_dir = output_root / "preflight_audit" / profile_mode.profile_key
            preflight_summary = preflight_dir / "summary.json"
            if args.resume and preflight_summary.exists():
                report = json.loads(preflight_summary.read_text(encoding="utf-8"))
                preflight[profile_mode.profile_key] = {
                    "status": report.get("status"),
                    "problem_count": len(report.get("problems", [])),
                    "summary_path": preflight_summary,
                    "resumed": True,
                }
                if report.get("status") != "pass":
                    raise RuntimeError(f"Existing static preflight audit failed; see {preflight_summary}")
            else:
                preflight[profile_mode.profile_key] = run_profile_preflight(
                    args.dataset,
                    profile_mode.profile_name,
                    args.preflight_sample_size,
                    preflight_dir,
                )
        base.save_json(output_root / "preflight_status.json", preflight)

    if not args.skip_prepare:
        base.preprocess_dataset(args.dataset, force=args.force_prepare)
        base.save_json(output_root / "prepare_status.json", {"hsage_counts": base.hsage_counts(args.dataset)})

    records_by_mode: dict[str, list[dict[str, Any]]] = {mode.name: [] for mode in modes}
    profile_run_snapshots: dict[tuple[str, int], dict[str, Any]] = {}

    for profile_mode in profile_modes:
        profile_root = output_root / "profiles" / profile_mode.profile_key
        profile_root.mkdir(parents=True, exist_ok=True)

        lower_snapshot_path = profile_root / "lower_profile_snapshot.json"
        if args.resume and lower_snapshot_path.exists():
            logger.info("Resuming lower profiles from snapshot profile_key={}", profile_mode.profile_key)
            restore_profiles_from_snapshot(args.dataset, lower_snapshot_path)
        elif not args.skip_lower_profiles:
            base.generate_profiles(
                args.dataset,
                profile_mode.profile_name,
                top_n=profile_mode.top_n,
                recreate=args.recreate_lower_profiles,
                layers=base.LOWER_LAYERS,
                max_entities_per_layer=args.max_profile_entities_per_layer,
                clear_existing_profiles=False,
                is_profile=profile_mode.is_profile,
                is_retriver=profile_mode.is_retriver,
                is_hsage=profile_mode.is_hsage,
                completion_cache_dir=profile_root / "completion_cache_lower_profiles",
            )
        base.require_profiles(
            args.dataset,
            profile_mode.profile_name,
            base.LOWER_LAYERS,
            args.max_profile_entities_per_layer,
        )
        lower_snapshot = base.snapshot_profiles(
            args.dataset,
            profile_mode.profile_name,
            base.LOWER_LAYERS,
            lower_snapshot_path,
        )
        base.save_json(
            profile_root / "lower_profile_status.json",
            {"profile_counts": base.profile_counts(args.dataset, profile_mode.profile_name), "snapshot": lower_snapshot},
        )

        for run_index in range(1, args.runs + 1):
            logger.info(
                "Generating layer5 profile profile_key={} run={}/{} dataset={}",
                profile_mode.profile_key,
                run_index,
                args.runs,
                args.dataset,
            )
            run_profile_dir = profile_root / f"run_{run_index:02d}"
            run_profile_dir.mkdir(parents=True, exist_ok=args.resume)
            intrusion_snapshot_path = run_profile_dir / "intrusion_profile_snapshot.json"
            if args.resume and intrusion_snapshot_path.exists():
                logger.info(
                    "Restoring layer5 profile from snapshot profile_key={} run={}",
                    profile_mode.profile_key,
                    run_index,
                )
                restore_profiles_from_snapshot(args.dataset, intrusion_snapshot_path)
            else:
                base.generate_profiles(
                    args.dataset,
                    profile_mode.profile_name,
                    top_n=profile_mode.top_n,
                    recreate=True,
                    layers=base.INTRUSION_LAYER,
                    max_entities_per_layer=args.max_profile_entities_per_layer,
                    clear_existing_profiles=True,
                    is_profile=profile_mode.is_profile,
                    is_retriver=profile_mode.is_retriver,
                    is_hsage=profile_mode.is_hsage,
                    completion_cache_dir=run_profile_dir / "completion_cache_profile",
                )
            base.require_profiles(
                args.dataset,
                profile_mode.profile_name,
                base.INTRUSION_LAYER,
                args.max_profile_entities_per_layer,
            )
            profile_run_snapshots[(profile_mode.profile_key, run_index)] = {
                "profile_counts": base.profile_counts(args.dataset, profile_mode.profile_name),
                "snapshot": base.snapshot_profiles(
                    args.dataset,
                    profile_mode.profile_name,
                    base.INTRUSION_LAYER,
                    intrusion_snapshot_path,
                ),
                "input_snapshot": base.snapshot_dataset_inputs(
                    args.dataset,
                    run_profile_dir / "input_snapshot_after_profile",
                ),
            }

            for mode in modes:
                if mode.profile_key != profile_mode.profile_key:
                    continue
                mode_root = output_root / f"mode_{mode.name}"
                mode_root.mkdir(parents=True, exist_ok=True)
                run_dir = mode_root / f"run_{run_index:02d}"
                run_dir.mkdir(parents=True, exist_ok=args.resume)
                completed_record = load_completed_record(run_dir) if args.resume else None
                if completed_record is not None:
                    logger.info("Skipping completed ablation mode={} run={} from metrics.json", mode.name, run_index)
                    records_by_mode[mode.name].append(completed_record)
                    continue
                run_started = time.time()
                logger.info(
                    "Starting ablation mode={} run={}/{} dataset={}",
                    mode.name,
                    run_index,
                    args.runs,
                    args.dataset,
                )
                input_snapshot_manifest = base.snapshot_dataset_inputs(
                    args.dataset,
                    run_dir / "input_snapshot_before_match",
                )
                match_record = base.run_match_and_eval(
                    args.dataset,
                    f"{run_id}_{mode.name}",
                    run_index,
                    run_dir,
                    mode.profile_name,
                    args.top_k,
                    is_ioc=mode.is_ioc,
                    is_hybrid=mode.is_hybrid,
                    intrusion_set_only_match=args.intrusion_set_only_match,
                    match_sample_size=args.match_sample_size,
                    source_target_input_path=None,
                    alignment_eval=False,
                )
                record = {
                    **match_record,
                    "run_total_seconds": time.time() - run_started,
                    "mode_config": asdict(mode) | {"profile_key": mode.profile_key},
                    "intrusion_set_only_match": args.intrusion_set_only_match,
                    "profile_run_snapshot": profile_run_snapshots[(profile_mode.profile_key, run_index)],
                    "input_snapshot_manifest": input_snapshot_manifest,
                    "profile_counts": base.profile_counts(args.dataset, mode.profile_name),
                }
                records_by_mode[mode.name].append(record)
                base.save_json(run_dir / "metrics.json", record)
                logger.info("Finished ablation mode={} run={} metrics={}", mode.name, run_index, record["metrics"])

    combined_summary: dict[str, Any] = {}
    for mode in modes:
        mode_root = output_root / f"mode_{mode.name}"
        summary = base.summarize_runs(
            records_by_mode[mode.name],
            mode_key(mode, args.top_k, args.intrusion_set_only_match),
        )
        combined_summary.update(summary)
        base.save_json(mode_root / "runs.json", records_by_mode[mode.name])
        base.save_json(mode_root / "summary.json", summary)
        base.write_summary_csv(mode_root / "summary.csv", args.dataset, summary)

    base.save_json(output_root / "runs.json", records_by_mode)
    base.save_json(output_root / "summary.json", combined_summary)
    base.write_summary_csv(output_root / "summary.csv", args.dataset, combined_summary)
    write_flat_runs_csv(output_root / "runs_flat.csv", records_by_mode)
    write_ablation_table(
        output_root / "ablation_table.md",
        combined_summary,
        modes,
        args.top_k,
        args.intrusion_set_only_match,
    )
    print(output_root)


if __name__ == "__main__":
    asyncio.run(main())
