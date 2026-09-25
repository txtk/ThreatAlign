alignment_index = {
    "properties": {
        "vector_profile": {"type": "dense_vector", "dims": 4096, "index": True, "similarity": "cosine"},
        "vector_profile_without_neighbour": {"type": "dense_vector", "dims": 4096, "index": True, "similarity": "cosine"},
        "vector_profile_without_enhance": {"type": "dense_vector", "dims": 4096, "index": True, "similarity": "cosine"},
        "vector_profile_without_retriver": {"type": "dense_vector", "dims": 4096, "index": True, "similarity": "cosine"},
        "content": {"type": "text"},
        "entity_type": {"type": "text"},
        "related_ioc": {"type": "keyword"},
    }
}

rag_malware = {
    "properties": {
        "name": {"type": "text"},
        "related_groups": {"type": "keyword"},
        "related_attcks": {"type": "keyword"},
        "vector": {"type": "dense_vector", "dims": 1024, "index": True, "similarity": "cosine"},
        "name_vector": {"type": "dense_vector", "dims": 1024, "index": True, "similarity": "cosine"},
        "raw_content": {"type": "text"},
    }
}

rag_attck = {
    "properties": {
        "name": {"type": "text"},
        "id": {"type": "text"},
        "related_groups": {"type": "keyword"},
        "related_malwares": {"type": "keyword"},
        "vector": {"type": "dense_vector", "dims": 1024, "index": True, "similarity": "cosine"},
        "name_vector": {"type": "dense_vector", "dims": 1024, "index": True, "similarity": "cosine"},
        "raw_content": {"type": "text"},
    }
}

rag_group = {
    "properties": {
        "name": {"type": "text"},
        "aliases": {"type": "keyword"},
        "raw_content": {"type": "text"},
        "related_attcks": {"type": "keyword"},
        "related_malwares": {"type": "keyword"},
        "vector": {"type": "dense_vector", "dims": 1024, "index": True, "similarity": "cosine"},
        "name_vector": {"type": "dense_vector", "dims": 1024, "index": True, "similarity": "cosine"},
    }
}
