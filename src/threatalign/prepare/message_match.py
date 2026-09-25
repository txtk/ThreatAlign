from utils.celery_task import get_embedding_celery
from utils.vector.vector_manager import ElasticsearchVectorManager

from .query_builder import QueryBuilder


def result_save(value, result):
    if "related_groups" in result:
        value["uncertain_related_groups"] = result["related_groups"]
    if "related_malware" in result:
        value["uncertain_related_malware"] = result["related_malware"]
    if "related_attack_patterns" in result:
        value["uncertain_related_attack_patterns"] = result["related_attack_patterns"]
    if "aliases" in result:
        value["uncertain_aliases"] = result["aliases"]
    if "id" in result:
        value["uncertain_id"] = result["id"]

    value["uncertain_name"] = result.get("name", "")
    value["uncertain_mes"] = result.get("raw_content", "")
    return value


def match_by_dict(query_builder, match_dict, rag_vector_manager: ElasticsearchVectorManager):
    for i in match_dict:
        for k, v in i.items():
            if k == "term":
                query = query_builder.build_term_query(v.get("field"), v.get("value"))
            elif k == "terms":
                query = query_builder.build_terms_query(v.get("field"), v.get("value"))
            elif k == "knn":
                query = query_builder.build_knn_query(
                    vector_field=v.get("field", ""),
                    query_vector=v.get("query_vector", []),
                    priority=False,
                )
            elif k == "match":
                query = query_builder.build_match_query(v.get("field"), v.get("value"))
            # Search and return the first hit above the threshold.
            hits, _ = rag_vector_manager.perform_search_detailed(query)
            for hit in hits:
                if k == "knn":
                    if hit.get("_score", 0) > 0.94:
                        return hit
                else:
                    if hit.get("_score", 0) > 5:
                        return hit
    return None


def message_match(attribute_dict, rag_malware, rag_attck, rag_group, force=False):
    query_builder = QueryBuilder()

    # 1. Collect names that need embeddings.
    names_to_embed = []
    items_to_process = []
    for _, value in attribute_dict.get_items():
        if value.get("processed") and not force:
            continue
        items_to_process.append(value)
        name = value.get("name", "").lower()
        if name and value.get("vector") is None:
            names_to_embed.append(name)

    # 2. Fetch embeddings in batch.
    if names_to_embed:
        unique_names = list(set(names_to_embed))
        embeddings = get_embedding_celery(unique_names)
        name_to_vector = dict(zip(unique_names, embeddings))

        for value in items_to_process:
            name = value.get("name", "").lower()
            if value.get("vector") is None and name in name_to_vector:
                value["vector"] = name_to_vector[name]

    # 3. Run the matching logic.
    for value in items_to_process:
        if force:
            value.pop("uncertain_related_groups", None)
            value.pop("uncertain_related_malware", None)
            value.pop("uncertain_related_attack_patterns", None)
            value.pop("aliases", None)

        name = value.get("name", "").lower()
        entity_type = value.get("entity_type", "")
        result = None

        vector = value.get("vector")
        if vector is None:
            continue

        if entity_type == "ThreatActor" or entity_type == "intrusion-set":
            match_dict = [
                {"term": {"field": "aliases", "value": name}},
                {"knn": {"field": "name_vector", "query_vector": vector}},
            ]
            result = match_by_dict(query_builder, match_dict, rag_group)
        elif entity_type == "Malware" or entity_type == "malware":
            match_dict = [
                {"match": {"field": "name", "value": name}},
                {"knn": {"field": "name_vector", "query_vector": vector}},
            ]
            result = match_by_dict(query_builder, match_dict, rag_malware)
        elif entity_type == "AttackPattern" or entity_type == "attack-pattern":
            match_dict = [
                {"match": {"field": "name", "value": name}},
                {"match": {"field": "id", "value": name}},
                {"knn": {"field": "name_vector", "query_vector": vector}},
            ]
            result = match_by_dict(query_builder, match_dict, rag_attck)
        if result:
            value = result_save(value, result)
        value["processed"] = True
    attribute_dict.save_json()


def threshold_experiment(attribute_dict, rag_malware, rag_attck, rag_group):
    """
    Estimate a useful KNN matching threshold from the data.
    1. Use strict text matching to identify high-confidence ground truth samples.
    2. Run KNN queries for these samples and record signal/noise scores.
    3. Print summary statistics and a zero-false-positive threshold suggestion.
    """

    query_builder = QueryBuilder()

    stats = {"correct_scores": [], "incorrect_scores": []}

    # Iterate over all attributes to be matched.
    items = list(attribute_dict.get_items())

    # 1. Fetch all missing embeddings in batch.
    names_to_embed = []
    for _, value in items:
        name = value.get("name", "").lower()
        if name and value.get("vector") is None:
            names_to_embed.append(name)

    if names_to_embed:
        unique_names = list(set(names_to_embed))
        embeddings = get_embedding_celery(unique_names)
        name_to_vector = dict(zip(unique_names, embeddings))
        for _, value in items:
            name = value.get("name", "").lower()
            if value.get("vector") is None and name in name_to_vector:
                value["vector"] = name_to_vector[name]

    for _, value in items:
        name = value.get("name", "").lower()
        entity_type = value.get("entity_type", "")
        if not name or not entity_type:
            continue

        # Read the vector.
        vector = value.get("vector")
        if vector is None:
            continue

        # Select the matching RAG manager and strict matching query.
        rag_manager = None
        strict_query = None

        if entity_type in ["ThreatActor", "intrusion-set"]:
            rag_manager = rag_group
            strict_query = query_builder.build_match_query("name", name, priority=False)
        elif entity_type in ["Malware", "malware"]:
            rag_manager = rag_malware
            strict_query = query_builder.build_match_query("name", name, priority=False)
        elif entity_type in ["AttackPattern", "attack-pattern"]:
            rag_manager = rag_attck
            strict_query = query_builder.build_match_query("name", name, priority=False)

        if not rag_manager or not strict_query:
            continue

        # 1. Use a strict score gate to select high-confidence ground-truth matches.
        # Lexical scores are usually higher; the gate is intentionally conservative.
        strict_results, _ = rag_manager.perform_search_detailed(strict_query)
        ground_truth_name = None
        if strict_results and strict_results[0].get("_score", 0) > 5:
            ground_truth_name = strict_results[0].get("name")

        if not ground_truth_name:
            continue

        # 2. Run KNN matching and collect scores for correct and incorrect hits.
        knn_query = query_builder.build_knn_query("name_vector", vector, priority=False)
        knn_results, _ = rag_manager.perform_search_detailed(knn_query)

        for res in knn_results:
            score = res.get("_score")
            # Record the score for the correct match.
            if res.get("name") == ground_truth_name:
                stats["correct_scores"].append(score)
            else:
                # Record non-matching scores as background noise.
                stats["incorrect_scores"].append(score)

    # Save computed vectors for reuse.
    attribute_dict.save_json()

    # 3. Print summary statistics.
    c_scores = stats["correct_scores"]
    i_scores = stats["incorrect_scores"]

    print("\n" + "=" * 60)
    print("                KNN Matching Threshold Analysis                ")
    print("=" * 60)
    print(f"Total processed entities: {attribute_dict.get_len()}")
    print(f"Ground-truth samples selected by strict matching: {len(c_scores)}")

    if not c_scores:
        print("No samples satisfy the strict matching condition. Increase the sample size or lower the strict threshold.")
        return

    print("\n[Correct-match (signal) KNN score statistics]")
    print(f"  Sample count: {len(c_scores)}")
    print(f"  Minimum: {min(c_scores):.5f}")
    print(f"  Maximum: {max(c_scores):.5f}")
    print(f"  Mean: {sum(c_scores) / len(c_scores):.5f}")

    if i_scores:
        print("\n[Incorrect-match (noise) KNN score statistics]")
        print(f"  Noise item count: {len(i_scores)}")
        print(f"  Maximum noise score: {max(i_scores):.5f}")
        print(f"  Mean noise score: {sum(i_scores) / len(i_scores):.5f}")

        max_noise = max(i_scores)
        min_signal = min(c_scores)

        print("\n[Threshold suggestion]")
        if min_signal > max_noise:
            print(f"Signal and noise are clearly separated (range: {max_noise:.5f} - {min_signal:.5f})。")
            print(f"--> Suggested threshold: {(min_signal + max_noise) / 2:.5f}")
        else:
            print(f"Signal and noise overlap (range: {min_signal:.5f} to {max_noise:.5f}).")
            # Find a zero-false-positive threshold.
            zero_fp_threshold = max_noise + 0.00001
            tp_above = sum(1 for s in c_scores if s >= zero_fp_threshold)
            recall = tp_above / len(c_scores)
            print(f"--> Suggested threshold for zero false positives: {zero_fp_threshold:.5f}")
            print(f"    Recall for correct matches at this threshold: {recall:.1%} ({tp_above}/{len(c_scores)})")
    else:
        print("\nNo noise items were found in the KNN results.")
        print(f"--> Suggested threshold based on the minimum signal score: {min(c_scores):.5f}")
    print("=" * 60 + "\n")
