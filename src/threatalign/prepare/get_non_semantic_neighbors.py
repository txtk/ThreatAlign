from loguru import logger

from threatalign.profile.get_profile import find_neighbours


def judge_semantic(triplets, target_id):
    no_semantics = []
    none_count = 0
    for triplet in triplets:
        start = triplet["start"]
        end = triplet["end"]
        if start is None or end is None:
            none_count += 1
            continue
        if start["unique_id"] == target_id:
            related_entity = end
        else:
            related_entity = start
        if related_entity.get("semantic") == 0:
            no_semantics.append(related_entity["name"])
    return no_semantics, none_count


def get_non_semantic_neighbors(suffix, attribute_dict, outgoing, incoming, entities):
    total_none_count = 0
    affected_entity_count = 0
    for id, entity in attribute_dict.get_items():
        start_triplets, end_triplets = find_neighbours(id, outgoing, incoming, entities, attribute_dict)
        triplets = start_triplets + end_triplets
        target_id = entity["unique_id"]
        no_semantic_neighbors, none_count = judge_semantic(triplets, target_id)
        if none_count > 0:
            affected_entity_count += 1
            total_none_count += none_count
            logger.warning(f"[{suffix}] entity {target_id} has {none_count} triplets with missing endpoints")
        entity["no_semantic_neighbors"] = no_semantic_neighbors
    logger.info(
        f"[{suffix}] non-semantic neighbor scan finished: missing-endpoint triplets={total_none_count}, affected entities={affected_entity_count}"
    )
