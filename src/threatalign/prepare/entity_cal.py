import math
import re
import zlib
from os import path

import numpy as np
import textstat
from elasticsearch.helpers import scan

from threatalign.profile.get_profile import find_neighbours
from config import elastic, settings
from utils.file.json_utils import JsonUtils

pattern = re.compile(r"[. _]")
textstat.set_lang("en_US")

# Count unique entities in knowledge-base indices.
def get_kb_counts(indices):
    unique_nums = []
    for index in indices:
        # Count unique entity identifiers.
        unique_names = set()
        # This field can vary by index; the current mappings consistently use 'name'.
        # rag_attck also has id; prefer id when available.

        query = {"query": {"match_all": {}}, "_source": ["name", "id"]}

        # Use scan for bulk retrieval.
        for doc in scan(elastic, index=index, query=query):
            source = doc.get("_source", {})
            name = source.get("name")
            entity_id = source.get("id")

            # For ATT&CK, prefer id as the unique identifier and fall back to name.
            if index == "rag_attck":
                identifier = entity_id or name
            else:
                identifier = name

            if identifier:
                unique_names.add(str(identifier).lower().strip())
        unique_nums.append(len(unique_names))
    return unique_nums


def get_layer_records(layer_json, entity_id_dict):
    for layer in list(layer_json.get_keys())[:-1]:
        for item in layer_json.get_value(layer):
            if item in entity_id_dict:
                yield layer, item, entity_id_dict[item]


def calculate_layer_nums(suffix, entity_id_dict, neo4j_type):
    layer_path = path.join(settings.json_dir, f"layer_{suffix}.json")
    layer_json = JsonUtils(layer_path)
    neo4j_static_dict = JsonUtils(path.join(settings.json_dir, f"neo4j_static_{suffix}.json"))
    layer_num_dict = {}
    item_layer_dict = {}

    for layer, item, records in get_layer_records(layer_json, entity_id_dict):
        if layer not in layer_num_dict:
            layer_num_dict[layer] = 0
        layer_num_dict[layer] += len(records)
        item_layer_dict[item] = layer
    neo4j_static_dict.set_value(neo4j_type, layer_num_dict)
    neo4j_static_dict.update(neo4j_type, item_layer_dict)
    neo4j_static_dict.save_json()


def entity_layer_num(start, end, target_id, neo4j_static_dict, target_layer, neo4j_type):
    neo4j_static_dict = neo4j_static_dict.get_value(neo4j_type)
    # start_type = list(start.keys())[0]
    # if start[start_type]["unique_id"] == target_id:
    if start["unique_id"] == target_id:
        related_entity = end
    else:
        related_entity = start
    # related_entity_type = list(related_entity.keys())[0]
    # related_entity = related_entity[related_entity_type]

    if related_entity.get("semantic") == 0:
        return None, 0
    related_entity_layer = neo4j_static_dict.get(related_entity["entity_type"])
    if int(related_entity_layer[-1]) > int(target_layer[-1]):
        return "up", 1
    elif int(related_entity_layer[-1]) < int(target_layer[-1]):
        return "down", related_entity.get("hsage")
    else:
        return "down", 1


def count_node_up_and_down(triplets, entity, neo4j_static_dict, layer, neo4j_type):
    """
    Count upper-layer and lower-layer neighbors for an entity in the graph.

    Args:
        triplets (list): Triple list where each item contains start and end nodes.
        entity (dict): Target entity with attributes such as unique_id.
        neo4j_static_dict (JsonDataset): Static graph metadata used to resolve entity layers.
        layer (str): Layer containing the target entity.

    Returns:
        tuple: (up_num, down_num) Counts/weights of upper-layer and lower-layer neighbors.
    """
    target_id = entity["unique_id"]
    up_num = 0
    down_num = 0
    for triplet in triplets:
        start = triplet["start"]
        end = triplet["end"]
        layer_type, result = entity_layer_num(start, end, target_id, neo4j_static_dict, layer, neo4j_type)
        if layer_type is None:
            continue
        elif layer_type == "up":
            up_num += result
        elif layer_type == "down":
            down_num += result
    return up_num, down_num


def count_up_total(layer, neo4j_static_dict, neo4j_type):
    layer_list = neo4j_static_dict.get_value("layer_list")
    up_layer_list = layer_list[layer_list.index(layer) + 1 :]

    up_total = 0
    for up_layer in up_layer_list:
        up_total += neo4j_static_dict.get_value(neo4j_type).get(up_layer, 0)
    return up_total

def count_down_total(layer, neo4j_static_dict, neo4j_type):
    layer_list = neo4j_static_dict.get_value("layer_list")
    down_layer_list = layer_list[:layer_list.index(layer)]

    down_total = neo4j_static_dict.get_value(neo4j_type).get(layer, 0)
    for down_layer in down_layer_list:
        down_total += neo4j_static_dict.get_value(neo4j_type).get(down_layer, 0)
    return down_total


def calculate_compression_complexity(text: str) -> float:
    """
    Compute compression-ratio complexity for text.

    The score is the ratio of compressed size to original size.
    A higher ratio indicates denser and less repetitive text.
    A lower ratio indicates more repetitive text.

    Args:
        text: Input string for complexity calculation.

    Returns:
        A float complexity score; returns 0.0 for empty or invalid input.
    """
    # Step 1: handle invalid input.
    # Treat empty or non-string input as zero complexity.
    if not text or not isinstance(text, str):
        return 0.0

    # Step 2: encode the string as bytes.
    # Compression algorithms operate on bytes rather than Python strings.
    # Use UTF-8 as a standard encoding.
    original_bytes = text.encode("utf-8")

    # Step 3: compress the byte sequence.
    compressed_bytes = zlib.compress(original_bytes)

    # Step 4: compute original and compressed sizes.
    original_size = len(original_bytes)
    compressed_size = len(compressed_bytes)

    # Check original size again to avoid division by zero.
    if original_size == 0:
        return 0.0

    # Step 5: compute and return the ratio.
    complexity_ratio = compressed_size / original_size

    return complexity_ratio


def weight_calculate(structural_scores, semantic_scores):
    structural_scores = np.array(structural_scores)
    semantic_scores = np.array(semantic_scores)

    # Compute means.
    mean_struct = np.mean(structural_scores)
    mean_sem = np.mean(semantic_scores)

    total_mean = mean_struct + mean_sem
    if total_mean == 0:
        w1, w2 = 0.5, 0.5
    else:
        w1 = mean_sem / total_mean
        w2 = mean_struct / total_mean
    return w1, w2

# If there is no upper-layer node, the term is zero.
def get_discrimination(up_num: int, up_total: int):
    if up_num == 0:
        return 0
    return math.log((up_total) / (up_num) + 1) + 1

# If there is no lower-layer node, the lower-layer corroboration term is one.
def get_corroboration_tesc(down_value: float, down_total: float):
    if down_value == 0:
        return 1
    return math.log(down_value / down_total + 1) + 1

# Compute graph-structure weight.
def get_tesc(up_num, up_total, down_value, down_total):
    d = get_discrimination(up_num, up_total)
    i = get_corroboration_tesc(down_value, down_total)
    return d * i


# Compute knowledge-base prior weight.
def get_pkc(entity, malware_total, attck_total, group_total):
    d = 0
    i = 0
    entity_type = entity.get("entity_type", "")
    malware_num = len(entity.get("uncertain_related_malwares", []))
    attack_num = len(entity.get("uncertain_related_attcks", []))
    group_num = len(entity.get("uncertain_related_groups", []))
    if entity_type == "AttackPattern" or entity_type == "attack-pattern":
        d = get_discrimination(0.3 * malware_num + 0.7 * group_num, 0.3 * malware_total + 0.7 * group_total)
        i = get_corroboration_tesc(0, 0)
    elif entity_type == "Malware" or entity_type == "malware":
        d = get_discrimination(group_num, group_total)
        i = get_corroboration_tesc(attack_num, attck_total)
    elif entity_type == "ThreatActor" or entity_type == "intrusion-set":
        d = get_discrimination(0, 0)
        i = get_corroboration_tesc(0.7 * malware_num + 0.3 * attack_num, 0.7 * malware_total + 0.3 * attck_total)
    return d * i


