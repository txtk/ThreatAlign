from utils.vector.RRF import RRF, RRF_Keyword_Retriever, RRF_Match_Retriever, RRF_Vector_Retriever


def make_result(res):
    result = {}
    result["name"] = res.get("name", "")
    result["content"] = res.get("raw_content", "")
    if "id" in res:
        result["id"] = res.get("id")
    if "aliases" in res:
        result["aliases"] = res.get("aliases")
    if "related_groups" in res:
        result["related_groups"] = res.get("related_groups")
    if "related_malware" in res:
        result["related_malware"] = res.get("related_malware")
    if "related_attack_patterns" in res:
        result["related_attack_patterns"] = res.get("related_attack_patterns")
    return result


def retriver_standard(neighbours_mes_dict, entity, rag_malware, rag_attck, rag_group):
    entity_type = entity.get("entity_type", "")
    retrievers = []

    if entity_type == "intrusion-set":
        malwares = neighbours_mes_dict.get("malware")
        attacks = neighbours_mes_dict.get("attack-pattern")
        if malwares:
            retrievers.append(
                RRF_Keyword_Retriever(item_name="related_malwares", keywords=[i.get("name") for i in malwares])
            )
        if attacks:
            retrievers.append(
                RRF_Keyword_Retriever(item_name="related_attcks", keywords=[i.get("name") for i in attacks])
            )
        retrievers.append(RRF_Keyword_Retriever(item_name="aliases", keywords=[entity.get("name")]))
        rag_manager = rag_group
    elif entity_type == "malware":
        groups = neighbours_mes_dict.get("intrusion-set")
        attacks = neighbours_mes_dict.get("attack-pattern")
        if groups:
            retrievers.append(
                RRF_Keyword_Retriever(item_name="related_groups", keywords=[i.get("name") for i in groups])
            )
        if attacks:
            retrievers.append(
                RRF_Keyword_Retriever(item_name="related_attcks", keywords=[i.get("name") for i in attacks])
            )
        retrievers.append(RRF_Match_Retriever(item_name="name", content=entity.get("name")))
        rag_manager = rag_malware
    elif entity_type == "attack-pattern":
        groups = neighbours_mes_dict.get("intrusion-set")
        malwares = neighbours_mes_dict.get("malware")
        if groups:
            retrievers.append(
                RRF_Keyword_Retriever(item_name="related_groups", keywords=[i.get("name") for i in groups])
            )
        if malwares:
            retrievers.append(
                RRF_Keyword_Retriever(item_name="related_malwares", keywords=[i.get("name") for i in malwares])
            )
        retrievers.append(RRF_Match_Retriever(item_name="name", content=entity.get("name")))
        retrievers.append(RRF_Match_Retriever(item_name="id", content=entity.get("name")))
        rag_manager = rag_attck
    else:
        return []

    if not retrievers:
        return []

    rrf = RRF()
    rrf.add_retrievers(retrievers)
    query = rrf.get_query()
    results, _ = rag_manager.perform_search_detailed(query, top_k=10)

    # Keep at most five entries with distinct names.
    unique_results = []
    seen_names = set()
    for res in results:
        name = res.get("name")
        if name and name not in seen_names:
            seen_names.add(name)
            result = make_result(res)
            unique_results.append(str({"Similar Entities": result}))
        if len(unique_results) >= 5:
            break
    return unique_results


def retriver_name(entity, vectors, rag_malware, rag_attck, rag_group):
    entity_type = entity.get("entity_type", "")
    entity_name = entity.get("name").lower()

    if entity_name.find("unknown") != -1 or entity_name.find("hidden") != -1:
        return []

    if entity_type == "intrusion-set":
        rag_manager = rag_group
    elif entity_type == "malware":
        rag_manager = rag_malware
    elif entity_type == "attack-pattern":
        rag_manager = rag_attck
    else:
        return []

    vector = vectors.get(entity.get("unique_id"))

    retrievers = []
    if vector:
        retrievers.append(RRF_Vector_Retriever(vector_field="vector", query_vector=vector))
        retrievers.append(RRF_Match_Retriever(item_name="raw_content", content=entity_name))

    # if entity_type == "intrusion-set":
    #     if entity_name:
    #         # For intrusion-set entities, use a term query against aliases.
    #         retrievers.append(RRF_Keyword_Retriever(item_name="aliases", keywords=[entity_name]))
    # elif entity_type == "attack-pattern":
    #     if entity_name:
    #         # For attack-pattern entities, use a match query against name.
    #         retrievers.append(RRF_Match_Retriever(item_name="name", content=entity_name))
    #     entity_id = entity.get("id")
    #     if entity_id:
    #         # For attack-pattern entities, use a match query against id.
    #         retrievers.append(RRF_Match_Retriever(item_name="id", content=entity_id))
    # else:
    #     if entity_name:
    #         # For malware entities, use a match query against name.
    #         retrievers.append(RRF_Match_Retriever(item_name="name", content=entity_name))

    if not retrievers:
        return []

    rrf = RRF()
    rrf.add_retrievers(retrievers)
    results, _ = rag_manager.perform_search_detailed(rrf.get_query(), top_k=3)
    related_results = []
    for res in results:
        result = make_result(res)
        related_results.append(str({"Content Related entity": result}))
    return related_results
