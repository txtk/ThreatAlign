from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from statistics import mean
from typing import Any


METRICS = (
    "hit1",
    "hit5",
    "hit10",
    "mrr",
    "ml_any_hit1",
    "ml_any_hit5",
    "ml_any_hit10",
    "ml_all_hit1",
    "ml_all_hit5",
    "ml_all_hit10",
    "aar_hit1",
    "aar_hit5",
    "aar_hit10",
    "aar_mrr",
)


def _positive_ranks(item: dict[str, Any], rank_key: str) -> list[int]:
    ranks = []
    for rank in item.get(rank_key, {}).values():
        try:
            rank_int = int(rank)
        except Exception:
            continue
        ranks.append(rank_int)
    return ranks


def _calculate_aar(valid_ranks: list[int]) -> float:
    ordered = sorted(valid_ranks)
    if not ordered:
        return 0.0
    total = 0.0
    for index, rank in enumerate(ordered, start=1):
        total += rank - index + 1
    return total / len(ordered)


def _init_bucket() -> dict[str, list[float]]:
    return {metric: [] for metric in METRICS}


def _add_sample_metrics(bucket: dict[str, list[float]], raw_ranks: list[int]) -> None:
    if not raw_ranks:
        return

    valid_ranks = [rank for rank in raw_ranks if rank > 0]

    # Conventional metrics: each GT label contributes one sample.
    for rank in raw_ranks:
        if rank <= 0:
            bucket["hit1"].append(0)
            bucket["hit5"].append(0)
            bucket["hit10"].append(0)
            bucket["mrr"].append(0.0)
        else:
            bucket["hit1"].append(1 if rank <= 1 else 0)
            bucket["hit5"].append(1 if rank <= 5 else 0)
            bucket["hit10"].append(1 if rank <= 10 else 0)
            bucket["mrr"].append(1.0 / rank)

    # Multi-label any/all metrics: each source entity contributes one sample.
    for k in (1, 5, 10):
        if valid_ranks:
            bucket[f"ml_any_hit{k}"].append(1 if min(valid_ranks) <= k else 0)
        else:
            bucket[f"ml_any_hit{k}"].append(0)
        if len(valid_ranks) == len(raw_ranks) and valid_ranks:
            bucket[f"ml_all_hit{k}"].append(1 if max(valid_ranks) <= k else 0)
        else:
            bucket[f"ml_all_hit{k}"].append(0)

    # Adjusted-average-rank metrics for multi-GT entities.
    if len(valid_ranks) != len(raw_ranks):
        bucket["aar_hit1"].append(0)
        bucket["aar_hit5"].append(0)
        bucket["aar_hit10"].append(0)
        bucket["aar_mrr"].append(0.0)
    else:
        aar = _calculate_aar(valid_ranks)
        bucket["aar_hit1"].append(1 if aar <= 1.000001 else 0)
        bucket["aar_hit5"].append(1 if aar < 5.0 else 0)
        bucket["aar_hit10"].append(1 if aar < 10.0 else 0)
        bucket["aar_mrr"].append(1.0 / aar if aar > 0 else 0.0)


def _summarize_bucket(bucket: dict[str, list[float]]) -> dict[str, float]:
    return {metric: mean(values) if values else 0.0 for metric, values in bucket.items()}


def evaluate_alignment_results(data: dict[str, Any], rank_key: str = "ground_truth_rank_new") -> dict[str, Any]:
    overall = _init_bucket()
    by_type: dict[str, dict[str, list[float]]] = defaultdict(_init_bucket)
    counts = {
        "samples": 0,
        "gt_labels": 0,
        "multilabel_samples": 0,
        "by_type": defaultdict(lambda: {"samples": 0, "gt_labels": 0, "multilabel_samples": 0}),
    }

    for item in data.values():
        raw_ranks = _positive_ranks(item, rank_key)
        if not raw_ranks:
            continue
        entity_type = item.get("entity_type", "unknown")
        counts["samples"] += 1
        counts["gt_labels"] += len(raw_ranks)
        if len(raw_ranks) > 1:
            counts["multilabel_samples"] += 1
        counts["by_type"][entity_type]["samples"] += 1
        counts["by_type"][entity_type]["gt_labels"] += len(raw_ranks)
        if len(raw_ranks) > 1:
            counts["by_type"][entity_type]["multilabel_samples"] += 1

        _add_sample_metrics(overall, raw_ranks)
        _add_sample_metrics(by_type[entity_type], raw_ranks)

    overall_summary = _summarize_bucket(overall)
    by_type_summary = {entity_type: _summarize_bucket(bucket) for entity_type, bucket in sorted(by_type.items())}
    counts["by_type"] = dict(sorted(counts["by_type"].items()))

    flat_metrics = {f"overall_{metric}": value for metric, value in overall_summary.items()}
    for entity_type, metrics in by_type_summary.items():
        safe_type = entity_type.replace("-", "_")
        for metric, value in metrics.items():
            flat_metrics[f"{safe_type}_{metric}"] = value

    return {
        "rank_key": rank_key,
        "counts": counts,
        "overall": overall_summary,
        "by_type": by_type_summary,
        "flat_metrics": flat_metrics,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate entity-alignment results with per-type and multi-label metrics.")
    parser.add_argument("results_path")
    parser.add_argument("--rank-key", default="ground_truth_rank_new")
    parser.add_argument("--output", default=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    results_path = Path(args.results_path)
    data = json.loads(results_path.read_text(encoding="utf-8"))
    report = evaluate_alignment_results(data, rank_key=args.rank_key)
    output = Path(args.output) if args.output else results_path.with_name("alignment_metrics_detailed.json")
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
