from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime
from pathlib import Path
from statistics import mean, pstdev, pvariance
from typing import Any

from threatalign.eval.eval_alignment_detailed import evaluate_alignment_results


DEFAULT_KEEP_TYPES = ("intrusion-set", "malware")


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")


def _summary(records: list[dict[str, Any]], mode_name: str) -> dict[str, Any]:
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


def _write_summary_csv(path: Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["mode", "metric", "runs", "mean", "variance", "std"])
        writer.writeheader()
        for mode, mode_data in summary.items():
            for metric, values in mode_data["metrics"].items():
                writer.writerow(
                    {
                        "mode": mode,
                        "metric": metric,
                        "runs": mode_data["runs"],
                        "mean": values["mean"],
                        "variance": values["variance"],
                        "std": values["std"],
                    }
                )


def _select_types(results: dict[str, Any], keep_types: tuple[str, ...]) -> dict[str, Any]:
    keep = set(keep_types)
    return {
        str(source_id): item
        for source_id, item in results.items()
        if isinstance(item, dict) and item.get("entity_type") in keep
    }


def merge_alignment_results(
    base_dir: Path,
    attack_dir: Path,
    output_dir: Path,
    runs: int,
    keep_base_types: tuple[str, ...] = DEFAULT_KEEP_TYPES,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    records = []
    metadata = {
        "created_at": datetime.now().astimezone().isoformat(),
        "base_dir": str(base_dir),
        "attack_dir": str(attack_dir),
        "output_dir": str(output_dir),
        "runs": runs,
        "keep_base_types": list(keep_base_types),
        "note": (
            "Merged old main-experiment intrusion-set/malware results with "
            "new attack-pattern-only alignment results."
        ),
    }
    _save_json(output_dir / "metadata.json", metadata)

    for run_index in range(1, runs + 1):
        run_name = f"run_{run_index:02d}"
        base_results_path = base_dir / run_name / "alignment_results.json"
        attack_results_path = attack_dir / run_name / "alignment_results.json"
        if not base_results_path.is_file():
            raise FileNotFoundError(f"Missing base results: {base_results_path}")
        if not attack_results_path.is_file():
            raise FileNotFoundError(f"Missing attack results: {attack_results_path}")

        base_results = _select_types(_load_json(base_results_path), keep_base_types)
        attack_results = _select_types(_load_json(attack_results_path), ("attack-pattern",))
        overlap = sorted(set(base_results) & set(attack_results))
        if overlap:
            raise RuntimeError(f"Unexpected overlapping source ids in {run_name}: {overlap[:10]}")

        merged = dict(base_results)
        merged.update(attack_results)

        run_dir = output_dir / run_name
        merged_path = run_dir / "alignment_results_merged.json"
        _save_json(merged_path, merged)
        detailed = evaluate_alignment_results(merged, rank_key="ground_truth_rank_new")
        detailed_path = run_dir / "alignment_metrics_detailed.json"
        _save_json(detailed_path, detailed)

        record = {
            "run": run_index,
            "base_results_path": str(base_results_path),
            "attack_results_path": str(attack_results_path),
            "merged_results_path": str(merged_path),
            "alignment_metrics_path": str(detailed_path),
            "counts": detailed["counts"],
            "metrics": detailed["flat_metrics"],
        }
        records.append(record)
        _save_json(run_dir / "metrics.json", record)

    mode_name = f"merged_base_types={','.join(keep_base_types)}+attack-pattern"
    summary = _summary(records, mode_name)
    _save_json(output_dir / "runs.json", records)
    _save_json(output_dir / "summary.json", summary)
    _write_summary_csv(output_dir / "summary.csv", summary)
    return {"metadata": metadata, "summary": summary}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Merge ThreatAlign base and attack-only alignment results.")
    parser.add_argument("--base-dir", required=True, help="Existing main-experiment log dir with intrusion/malware results.")
    parser.add_argument("--attack-dir", required=True, help="Attack-pattern-only alignment log dir.")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--keep-base-types", nargs="+", default=list(DEFAULT_KEEP_TYPES))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = merge_alignment_results(
        Path(args.base_dir),
        Path(args.attack_dir),
        Path(args.output_dir),
        runs=args.runs,
        keep_base_types=tuple(args.keep_base_types),
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    main()
