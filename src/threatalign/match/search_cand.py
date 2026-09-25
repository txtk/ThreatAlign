import copy
import hashlib
import json
from collections import defaultdict
from typing import Any, Dict, List

from utils.celery_task import get_completion_result_batch, get_completion_result_batch_cached
from utils.vector.query_builders import (
    BoolQueryBuilder,
    TermsQueryBuilder,
)
from utils.vector.RRF import RRF, RRF_Match_Retriever, RRF_Vector_Retriever

from .save import save_result


def _content_cache_key(prefix: str, entity_id: str, content: dict) -> str:
    payload = json.dumps(content, ensure_ascii=False, sort_keys=True)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"{prefix}:{entity_id}:{digest}"


def parse_results(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Parse Elasticsearch search results."""
    return [
        {
            "id": hit.get("_id"),
            "profile": hit.get("_source", {}).get("content", ""),
        }
        for hit in results
    ]


def search_by_ioc(results_dict, attribute_dict, es_manager, top_k=10) -> Dict:
    id_iocs_cand = {}
    for entity_id in results_dict:
        entity = attribute_dict.get_value(str(entity_id))
        ioc_list = entity.get("no_semantic_neighbors", [])
        entity_type = entity.get("entity_type", "")

        bool_builder = BoolQueryBuilder()
        has_condition = False
        if ioc_list:
            bool_builder.add_must(TermsQueryBuilder(field="related_ioc", values=ioc_list))
            has_condition = True

        if has_condition:
            query = bool_builder.get_query()
            results = es_manager.perform_search(query, top_k=top_k)
            for i in results[:]:
                if i["_source"]["entity_type"] != entity_type:
                    results.remove(i)
            id_iocs_cand[entity_id] = parse_results(results)

    return id_iocs_cand


def search_by_profile(
    results_dict,
    attribute_dict,
    source_vectors,
    es_manager,
    profile_name,
    is_hybrid_mode,
    top_k=10,
) -> Dict:
    id_profile_cand = {}
    for entity_id in results_dict:
        entity = attribute_dict.get_value(str(entity_id))
        profile = results_dict[entity_id].get(profile_name, "")
        entity_type = entity.get("entity_type", "")

        retrievers = [
            RRF_Match_Retriever(item_name="entity_type", content=entity_type),
            RRF_Vector_Retriever(vector_field=f"vector_{profile_name}", query_vector=source_vectors[entity_id]),
        ]

        if is_hybrid_mode:
            retrievers.insert(0, RRF_Match_Retriever(item_name="content", content=profile))

        rrf = RRF().add_retrievers(retrievers)
        query = rrf.get_query()

        if "retriever" in query and "rrf" in query["retriever"]:
            query["retriever"]["rrf"]["rank_window_size"] = max(top_k, 50)

        results = es_manager.perform_search(query.copy(), top_k=top_k)

        # Compute ground-truth rank.
        # If the rank is within top_k, the profile candidate is available for later re-ranking.
        gt_ids = results_dict[entity_id].get("groud_truth", "")
        results_dict[entity_id]["ground_truth_rank"] = {}
        for gt_id in gt_ids:
            rank = -1
            if gt_id:
                # Check whether the ground truth is in the top_k results.
                for idx, hit in enumerate(results):
                    if hit["_id"] == str(gt_id):
                        rank = idx + 1
                        break

                # If it is not found in the first results, expand the search window to estimate the rank.
                if rank == -1:
                    deep_query = query.copy()
                    if "size" in deep_query:
                        del deep_query["size"]
                    deep_query["_source"] = False  # Only IDs are needed for rank calculation.

                    # RRF requires rank_window_size >= size.
                    if "retriever" in deep_query and "rrf" in deep_query["retriever"]:
                        deep_query["retriever"]["rrf"]["rank_window_size"] = 10000

                    # Assume the candidate store does not exceed 10000 entries, or only the first 10000 ranks matter.
                    deep_results = es_manager.perform_search(deep_query, top_k=10000)
                    for idx, hit in enumerate(deep_results):
                        if hit["_id"] == str(gt_id):
                            rank = idx + 1
                            break

            results_dict[entity_id]["ground_truth_rank"][str(gt_id)] = rank

            id_profile_cand[entity_id] = parse_results(results)
    return id_profile_cand


def make_content(idx, cand_dict, attribute_dict, name_to_id, results_dict=None, candidate_source="unknown") -> List[Dict[str, str]]:
    candidates = cand_dict.get(idx, [])
    content = []
    for cand in candidates:
        cand_id = cand["id"]
        target_entity = attribute_dict.get_value(str(cand_id))
        if target_entity is None:
            if results_dict is not None:
                results_dict[idx].setdefault("missing_candidate_ids", []).append(
                    {"candidate_source": candidate_source, "candidate_id": cand_id}
                )
            continue
        # Use candidate entity names as keys.
        name = target_entity.get("name", "")
        content.append({name: cand["profile"]})
        name_to_id[name].add(cand_id)
    return content


def search_candidates(
    results_dict,
    source_attribute_dict,
    target_attribute_dict,
    source_vectors,
    es_manager,
    profile_name,
    is_ioc_mode,
    is_hybrid_mode,
    direct_prompt_path,
    results_path,
    completion_cache_path=None,
    top_k=10,
):
    ioc_cand_dict = {}
    if is_ioc_mode:
        ioc_cand_dict = search_by_ioc(results_dict, source_attribute_dict, es_manager, top_k=top_k)

    profile_cand_dict = search_by_profile(
        results_dict,
        source_attribute_dict,
        source_vectors,
        es_manager,
        profile_name,
        is_hybrid_mode,
        top_k=top_k,
    )

    ids = []
    contents = []
    name_to_id = defaultdict(set)
    for entity_id in results_dict:
        entity = results_dict.get(entity_id)

        # Optimization: check whether the ground truth is in the candidate set.
        # If the ground truth is neither in the profile top-k nor in the IoC search results,
        # the sample does not need downstream model reranking.
        # gt_ids = entity.get("groud_truth", [])

        # # Collect IDs returned by IoC search.
        # ioc_cands = ioc_cand_dict.get(entity_id, [])
        # ioc_cand_ids = {str(c["id"]) for c in ioc_cands}

        # valid_sample = False
        # for gt_id in gt_ids:
        #     gt_id = str(gt_id)
        #     # 1. Check whether the profile rank is within top-k.
        #     # search_by_profile has already computed the rank; <= top_k means it is in candidates.
        #     rank = entity.get("ground_truth_rank", {}).get(gt_id, -1)
        #     flag_profile = rank != -1 and rank <= top_k

        #     # 2. Check whether it appears in the IoC search results.
        #     flag_ioc = gt_id in ioc_cand_ids

        #     if flag_profile or flag_ioc:
        #         valid_sample = True
        #         break

        # if not valid_sample:
        #     results_dict[entity_id]["ground_truth_rank_new"] = copy.deepcopy(entity.get("ground_truth_rank", {}))
        #     results_dict[entity_id]["candidates"] = []
        #     continue

        ioc_content = []
        if is_ioc_mode:
            ioc_content = make_content(
                entity_id,
                ioc_cand_dict,
                target_attribute_dict,
                name_to_id,
                results_dict=results_dict,
                candidate_source="ioc",
            )

        profile_content = make_content(
            entity_id,
            profile_cand_dict,
            target_attribute_dict,
            name_to_id,
            results_dict=results_dict,
            candidate_source="profile",
        )

        self_info = {
            "name": entity.get("name", ""),
            "entity_type": entity.get("entity_type", ""),
            "profile": entity.get(profile_name, ""),
        }
        content = {
            "self_info": self_info,
            "ioc_candidates": ioc_content,
            "profile_candidates": profile_content,
        }
        ids.append(entity_id)
        contents.append(content)

    if completion_cache_path is None:
        results = get_completion_result_batch(contents, str(direct_prompt_path))
    else:
        cache_keys = [
            _content_cache_key("match_rerank", entity_id, content)
            for entity_id, content in zip(ids, contents)
        ]
        results = get_completion_result_batch_cached(
            contents,
            str(direct_prompt_path),
            completion_cache_path,
            cache_keys=cache_keys,
        )

    save_result(ids, results, results_dict, name_to_id, results_path)
