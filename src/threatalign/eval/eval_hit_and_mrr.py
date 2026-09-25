from typing import Any, Dict, List

import numpy as np


def calculate_aar(ranks: List[int]) -> float:
    """
    Calculate Average Adjusted Rank (AAR)
    ranks: List of original ranks of ground truth entities, sorted ascending.
    """
    ranks.sort()
    m = len(ranks)
    if m == 0:
        return 0.0

    total_adjusted_rank = 0
    # Formula given: AAR(e) = (1/m) * sum( r_k - k + 1 )
    # where r_k is the k-th smallest rank, and k is 1-based index (1..m)
    for k_0, r_k in enumerate(ranks):
        k = k_0 + 1
        term = r_k - k + 1
        total_adjusted_rank += term

    return total_adjusted_rank / m


def eval_hit_and_mrr(data: Dict[str, Any], rank_key: str = "ground_truth_rank_new"):
    metrics = {
        "hit1": [],
        "hit5": [],
        "hit10": [],
        "mrr": [],
        "aar_hit1": [],
        "aar_hit5": [],
        "aar_hit10": [],
        "aar_mrr": [],
    }

    type_metrics = {}

    for key, item in data.items():
        entity_type = item.get("entity_type", "unknown")
        if entity_type not in type_metrics:
            type_metrics[entity_type] = {
                "hit1": [],
                "hit5": [],
                "hit10": [],
                "mrr": [],
                "aar_hit1": [],
                "aar_hit5": [],
                "aar_hit10": [],
                "aar_mrr": [],
            }

        gt_ranks_dict = item.get(rank_key, {})
        # Fallback if specific key is empty? User asked to input the attribute name.
        # I should probably respect the input. But what if they pass 'ground_truth_rank' and I see 'ground_truth_rank_new'?
        # I will strictly use the provided key as primary, maybe no fallback or simple fallback if empty.
        # But for backward compatibility with previous logic:
        # User said "I input ... ground_truth_rank attribute name". I should use that.

        # If not gt_ranks_dict, try the other common one?
        # Let's clean this up to use the passed key.

        # If no ground truth rank info, skip
        if not gt_ranks_dict:
            continue
            continue

        # Rank -1 means the ground-truth entity was not found in the search
        # window. It must not be counted as Hit@1/5/10, and using 1 / -1
        # would make MRR negative. Keep the miss as a zero contribution for
        # conventional metrics, and only compute AAR when every GT has a valid
        # positive rank.
        raw_ranks = sorted([int(r) for r in gt_ranks_dict.values()])
        valid_ranks = [r for r in raw_ranks if r > 0]

        # --- Conventional Metrics (each GT is a sample) ---
        for r in raw_ranks:
            if r <= 0:
                h1 = h5 = h10 = 0
                mrr = 0.0
            else:
                h1 = 1 if r <= 1 else 0
                h5 = 1 if r <= 5 else 0
                h10 = 1 if r <= 10 else 0
                mrr = 1.0 / r

            metrics["hit1"].append(h1)
            metrics["hit5"].append(h5)
            metrics["hit10"].append(h10)
            metrics["mrr"].append(mrr)

            type_metrics[entity_type]["hit1"].append(h1)
            type_metrics[entity_type]["hit5"].append(h5)
            type_metrics[entity_type]["hit10"].append(h10)
            type_metrics[entity_type]["mrr"].append(mrr)

        # --- AAR Metrics ---
        if len(valid_ranks) != len(raw_ranks):
            aar_h1 = aar_h5 = aar_h10 = 0
            aar_mrr_val = 0.0
        else:
            aar = calculate_aar(valid_ranks)

            # hit1 only if AAR == 1 (or close enough for float)
            # Hit@1 succeeds only when the averaged ground-truth rank is 1.
            aar_h1 = 1 if aar <= 1.000001 else 0

            # Hit@5/10 succeeds when the averaged ground-truth rank is within 5 or 10.
            aar_h5 = 1 if aar < 5.0 else 0
            aar_h10 = 1 if aar < 10.0 else 0

            # MRR based on AAR
            aar_mrr_val = 1.0 / aar if aar > 0 else 0

        metrics["aar_hit1"].append(aar_h1)
        metrics["aar_hit5"].append(aar_h5)
        metrics["aar_hit10"].append(aar_h10)
        metrics["aar_mrr"].append(aar_mrr_val)

        type_metrics[entity_type]["aar_hit1"].append(aar_h1)
        type_metrics[entity_type]["aar_hit5"].append(aar_h5)
        type_metrics[entity_type]["aar_hit10"].append(aar_h10)
        type_metrics[entity_type]["aar_mrr"].append(aar_mrr_val)

    # Output Results
    print("Overall Performance:")
    overall_res = print_metrics(metrics)

    print("\nPerformance by Entity Type:")
    for t_name, t_data in type_metrics.items():
        print(f"Type: {t_name}")
        print_metrics(t_data)

    return overall_res


def print_metrics(metrics_dict):
    desired_order = ["hit1", "hit5", "hit10", "mrr", "aar_hit1", "aar_hit5", "aar_hit10", "aar_mrr"]
    res = {}
    for m_name in desired_order:
        if m_name in metrics_dict and metrics_dict[m_name]:
            avg = np.mean(metrics_dict[m_name])
            print(f"  {m_name}: {avg:.4f}")
            res[m_name] = avg
        else:
            print(f"  {m_name}: N/A")
            res[m_name] = 0.0
    return res
