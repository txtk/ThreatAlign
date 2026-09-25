import copy

from json_repair import repair_json
from loguru import logger

from config import settings
from utils.celery_task import get_embedding_celery
from utils.file.file_utils import FileUtils
from utils.file.json_utils import JsonUtils
from utils.vector.get_vector import load_vector_pkl
from utils.vector.vector_manager import ElasticsearchVectorManager


def profile_clean(profile):
    start = profile.find("[profile]")
    end = profile.find("[/profile]")
    profile = profile[start + 9 : end].strip()
    return profile


def insert_target_data(
    es_manager: ElasticsearchVectorManager, result_dict: dict, attribute_dict: JsonUtils, profile_name, recreate=False
):
    if not recreate and es_manager.count_documents() > 0:
        logger.info(f"Index '{es_manager.index_name}' already contains data; skipping insert.")
        return
    id_to_data = {}  # id -> {content, entity_type, related_ioc}
    for v in result_dict.values():
        for i in v.get("groud_truth", []):
            if i not in id_to_data:
                target_entity = attribute_dict.get_value(str(i))
                id_to_data[i] = {
                    "content": profile_clean(target_entity.get(profile_name, "")),
                    "entity_type": target_entity.get("entity_type", ""),
                    "related_ioc": target_entity.get("no_semantic_neighbors", []),
                }

    if not id_to_data:
        return

    ids = list(id_to_data.keys())
    all_contents = [id_to_data[i]["content"] for i in ids]
    unique_contents = list(set(all_contents))

    # Get embeddings for unique contents only
    embeddings = get_embedding_celery(unique_contents, settings.embedding_dimension_att)
    content_to_vector = dict(zip(unique_contents, embeddings))

    docs = []
    for i in ids:
        content = id_to_data[i]["content"]
        doc = {
            "_id": i,
            "content": content,
            f"vector_{profile_name}": content_to_vector[content],
            "entity_type": id_to_data[i]["entity_type"],
            "related_ioc": id_to_data[i]["related_ioc"],
        }
        docs.append(doc)
    es_manager.index_document(docs)


def save_source_vector(source_vector_path, result_dict: dict, attribute_dict: JsonUtils, profile_name, recreate=False):
    if FileUtils.exist_file(source_vector_path) and not recreate:
        return load_vector_pkl(source_vector_path)

    id_to_content = {}
    for k, v in result_dict.items():
        if k not in id_to_content:
            id_to_content[k] = v.get(profile_name)

    if not id_to_content:
        return {}

    unique_contents = list(set(id_to_content.values()))
    embeddings = get_embedding_celery(unique_contents, settings.embedding_dimension_att)
    content_to_vector = dict(zip(unique_contents, embeddings))

    vectors = {i: content_to_vector[content] for i, content in id_to_content.items()}
    FileUtils.save_file(vectors, source_vector_path)
    return vectors


def save_result(ids, results, results_dict, name_to_id, results_path):
    for idx, res in zip(ids, results):
        # Use json_repair to robustly parse JSON that may contain Markdown or minor formatting errors.
        results_dict[idx]["ground_truth_rank_new"] = copy.deepcopy(results_dict[idx].get("ground_truth_rank"))
        results_dict[idx]["candidates"] = []
        try:
            parsed_res = repair_json(res, return_objects=True).get("top_10_results")
            for rank, res in reversed(list(enumerate(parsed_res))):
                name = res.get("entity_name")
                # reasoning = res.get("reasoning")
                ids = name_to_id.get(name)
                if ids:
                    for id in ids:
                        if id in results_dict[idx].get("ground_truth_rank_new"):
                            results_dict[idx]["ground_truth_rank_new"][id] = rank + 1

            if not isinstance(parsed_res, list):
                parsed_res = []
        except Exception:
            parsed_res = []
        results_dict[idx]["candidates"] = parsed_res

    JsonUtils().save_json(results_dict, results_path)
