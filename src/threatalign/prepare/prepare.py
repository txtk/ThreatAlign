from os import path
from pathlib import Path

from threatalign.make_adj import find_directed_links
from config import settings
from utils.file.file_utils import FileUtils
from utils.file.json_utils import JsonUtils
from utils.name_process import semantic_judge

from .entity_cal import calculate_layer_nums, get_kb_counts
from .get_non_semantic_neighbors import get_non_semantic_neighbors
from .importance import importance
from .message_match import message_match
from utils.vector.get_vector import load_vector_pkl


RAG_STATISTIC_KEYS = ["malware_count", "attck_count", "group_count"]


def _load_existing_rag_statistics(current_path):
    for name in ["rag_statistic_heaa_random.json", "rag_statistic_heaa_time.json"]:
        statistic = JsonUtils(path.join(settings.json_dir, name))
        if statistic.data and all(k in statistic.data for k in RAG_STATISTIC_KEYS):
            if Path(current_path).name != name:
                statistic.save_json({k: statistic.get_value(k) for k in RAG_STATISTIC_KEYS}, current_path)
            return [statistic.get_value(k) for k in RAG_STATISTIC_KEYS]
    return None


def recheck_semantic(attribute_dict):
    for _, value in attribute_dict.get_items():
        name = value.get("name", "")
        if semantic_judge(name):
            value["semantic"] = 1
        else:
            value["semantic"] = 0
    attribute_dict.save_json()


def pre_process(suffix, root_dir, graph_type, rag_malware, rag_attck, rag_group, force=False):
    statistic_dict_path = path.join(settings.json_dir, f"rag_statistic_{suffix}.json")
    statistic_dict = JsonUtils(statistic_dict_path)
    if statistic_dict.data and all(k in statistic_dict.data for k in RAG_STATISTIC_KEYS):
        malware_count = statistic_dict.get_value("malware_count")
        attck_count = statistic_dict.get_value("attck_count")
        group_count = statistic_dict.get_value("group_count")
    else:
        existing_statistics = _load_existing_rag_statistics(statistic_dict_path)
        if existing_statistics:
            malware_count, attck_count, group_count = existing_statistics
        else:
            malware_count, attck_count, group_count = get_kb_counts(["rag_malware", "rag_attck", "rag_group"])
            statistic_dict.set_value("malware_count", malware_count)
            statistic_dict.set_value("attck_count", attck_count)
            statistic_dict.set_value("group_count", group_count)
            statistic_dict.save_json()
    attribute_path = path.join(root_dir, f"{graph_type}_attributes.json")
    attribute_dict = JsonUtils(attribute_path)
    entity_id_dict_path = path.join(root_dir, f"{graph_type}_entity_type_id.json")
    entity_id_dict = JsonUtils(entity_id_dict_path).data
    tuple_path = path.join(root_dir, f"{graph_type}_tuples.txt")
    outgoing, incoming, entities = find_directed_links(tuple_path)
    recheck_semantic(attribute_dict)
    get_non_semantic_neighbors(suffix, attribute_dict, outgoing, incoming, entities)
    # threshold_experiment(attribute_dict, rag_malware, rag_attck, rag_group)
    message_match(attribute_dict, rag_malware, rag_attck, rag_group, force=force)
    calculate_layer_nums(suffix, entity_id_dict, graph_type)
    importance(
        suffix,
        attribute_dict,
        entity_id_dict,
        graph_type,
        outgoing,
        incoming,
        entities,
        malware_count,
        attck_count,
        group_count,
    )
    vector_path = path.join(root_dir, f"{graph_type}_vectors.pkl")
    if FileUtils.exist_file(vector_path) and not force:
        vector_data = load_vector_pkl(vector_path)
    else:
        vector_data = {}
    for _, value in attribute_dict.get_items():
        if "vector" in value:
            key = value.get("unique_id")
            vector_data[key] = value.pop("vector")
        if "entity_type" in value:
            if value["entity_type"] == "ThreatActor":
                value["entity_type"] = "intrusion-set"
            elif value["entity_type"] == "Malware":
                value["entity_type"] = "malware"
            elif value["entity_type"] == "AttackPattern":
                value["entity_type"] = "attack-pattern"
    FileUtils.save_file(vector_data, vector_path)
    attribute_dict.save_json()
