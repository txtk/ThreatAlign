import math
from config import settings

from .entity_cal import get_pkc, get_tesc, get_layer_records, find_neighbours, count_node_up_and_down, count_down_total, count_up_total
from os import path
from utils.file.json_utils import JsonUtils
from collections import defaultdict


def importance(suffix, attribute_dict, entity_id_dict, neo4j_type, outgoing, incoming, entities, malware_count, attck_count, group_count):
    layer_path = path.join(settings.json_dir, f"layer_{suffix}.json")
    layer_json = JsonUtils(layer_path)
    neo4j_static_dict = JsonUtils(path.join(settings.json_dir, f"neo4j_static_{suffix}.json"))
    layer_hsage_dict = defaultdict(lambda: 0)

    for layer, item, records in get_layer_records(layer_json, entity_id_dict):
        up_total = count_up_total(layer, neo4j_static_dict, neo4j_type)
        down_total = count_down_total(layer, neo4j_static_dict, neo4j_type)
        for record in records:
            entity = attribute_dict.get_value(str(record))
            if entity["semantic"] == 0:
                entity["hsage"] = 0
            else:
                start_triplets, end_triplets = find_neighbours(record, outgoing, incoming, entities, attribute_dict)
                triplets = start_triplets + end_triplets
                up_num, down_value = count_node_up_and_down(triplets, entity, neo4j_static_dict, layer, neo4j_type)
                tesc = get_tesc(up_num, up_total, down_value, down_total)
                pkc = get_pkc(entity, malware_count, attck_count, group_count)
                entity["hsage"] = tesc + pkc
                layer_hsage_dict[layer] += entity["hsage"]
            
            if "importance" in entity:
                entity.pop("importance")
    attribute_dict.save_json()
