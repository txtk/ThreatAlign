from loguru import logger

from config import settings
from config.mappings import alignment_index
from utils.file.json_utils import JsonUtils
from utils.file.path_utils import PathUtils
from utils.vector.vector_manager import ElasticsearchVectorManager

from .save import insert_target_data, profile_clean, save_source_vector
from .search_cand import search_candidates


def get_source_target_labels(
    source_target_dict: JsonUtils, results_dict: dict, source_attribute_dict: JsonUtils, profile_name, intrusio_set_mode
):
    for k, v in source_target_dict.get_items():
        entity = source_attribute_dict.get_value(str(k))
        entity_type = entity.get("entity_type", "")
        if intrusio_set_mode:
            if entity_type != "intrusion-set":
                continue
        elif entity_type != "intrusion-set" and entity_type != "malware" and entity_type != "attack-pattern":
            continue
        result = {
            "name": entity.get("name", ""),
            "entity_type": entity.get("entity_type", ""),
            "groud_truth": v,
            profile_name: profile_clean(entity.get(profile_name, "")),
        }
        results_dict[k] = result
    return results_dict


def match(
    suffix,
    source_target_path,
    target_attribute_path,
    source_attribute_path,
    source_tuple_path,
    profile_name,
    is_ioc_mode,
    is_hybrid_mode,
    intrusio_set_mode,
    top_k,
    recreate=False,
    results_path=None,
    index_name=None,
    source_vector_path=None,
    completion_cache_path=None,
):
    es_manager = ElasticsearchVectorManager(index_name=index_name or f"alignment_{suffix}", mappings=alignment_index)
    if recreate:
        es_manager.delete_index()
    es_manager.create_index()
    results_dict = {}
    source_target_dict = JsonUtils(source_target_path)
    target_attributes = JsonUtils(target_attribute_path)
    source_attributes = JsonUtils(source_attribute_path)
    if source_vector_path is None:
        source_vector_path = PathUtils.path_concat(settings.dataset_dir, suffix, f"source_{profile_name}_vector.pkl")
    # direct_prompt_path = PathUtils.path_concat(settings.prompt_dir, "alignment", "direct_no_evidence.poml")
    direct_prompt_path = PathUtils.path_concat(settings.prompt_dir, "alignment", "direct.poml")

    if results_path is None:
        results_path = PathUtils.path_concat(
            settings.result_log_dir,
            f"alignment_{suffix}_{profile_name}_ioc: {is_ioc_mode}_hybrid: {is_hybrid_mode}_topk: {top_k}.json",
        )
    if PathUtils.exist_path(results_path) and not recreate:
        logger.info(f"Result file already exists; skipping matching: {results_path}")
        return results_path

    # source_outgoing, source_incoming, source_entities = find_directed_links(source_tuple_path)
    get_source_target_labels(source_target_dict, results_dict, source_attributes, profile_name, intrusio_set_mode)
    insert_target_data(es_manager, results_dict, target_attributes, profile_name, recreate=recreate)
    source_vectors = save_source_vector(
        source_vector_path, results_dict, source_attributes, profile_name, recreate=recreate
    )
    results_dict = search_candidates(
        results_dict,
        source_attributes,
        target_attributes,
        source_vectors,
        es_manager,
        profile_name,
        is_ioc_mode,
        is_hybrid_mode,
        direct_prompt_path,
        results_path,
        completion_cache_path=completion_cache_path,
        top_k=top_k,
    )
    return results_path
