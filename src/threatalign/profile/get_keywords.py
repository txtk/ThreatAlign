from utils.name_process import get_name



def json_init(input_dict, key, inital_value):
    if key not in input_dict:
        input_dict[key] = inital_value
    return input_dict


def insert_property_dict(entity, entity_type, profile_dict, last_items, property_name="profile"):
    """
    Append each entity profile and NF-IPF value as a dictionary item.
    """
    # Return immediately when semantic is not 1.
    if entity.get(entity_type, {}).get("semantic") != 1:
        return profile_dict

    if entity_type in last_items:
        # Ensure the entity_type key exists and stores a list.
        profile_dict = json_init(profile_dict, entity_type, [])

        # Create a dictionary containing profile and nf_ipf.
        profile_data = {
            property_name: entity[entity_type].get(property_name),
            "nf_ipf": entity[entity_type].get("nfipf", 0) # Use .get to avoid missing nf_ipf errors; default to 0.
        }
        
        # Append the new dictionary to the list.
        profile_dict[entity_type].append(profile_data)

    return profile_dict

def insert_semantic_dict(entity, entity_type, keyword_dict, last_items):
    # Return immediately when semantic is not 1.
    if entity.get("semantic") != 1:
        return keyword_dict

    if entity_type in last_items:
        # Ensure the entity_type key exists and stores a list.
        keyword_dict = json_init(keyword_dict, entity_type, [])

        # Create a dictionary containing profile and nf_ipf.
        keyword_data = {
            "keywords": get_name(entity),
            "nf_ipf": entity.get("nf_ipf", 0) # Use .get to avoid missing nf_ipf errors; default to 0.
        }
        
        # Append the new dictionary to the list.
        keyword_dict[entity_type].append(keyword_data)

    return keyword_dict


def generate_keyword_dict(keyword_dict, triples, mode, last_items):
    for triple in triples:
        if mode == "start":
            end = triple["end"]
            end_type = end.get("entity_type")
            keyword_dict = insert_semantic_dict(end, end_type, keyword_dict, last_items)

        else:
            start = triple["start"]
            start_type = start.get("entity_type")
            keyword_dict = insert_semantic_dict(start, start_type, keyword_dict, last_items)

    return keyword_dict


def finalize_and_sort_profiles(input_dict, key_name, top_n=5):
    """
    Process each entity-type list in profile_dict:
    1. Sort by nf_ipf in descending order.
    2. Keep only the first top_n items.
    3. Extract profile text so the final list contains strings only.
    """
    final_dict = {}
    for entity_type, profiles_with_scores in input_dict.items():
        # 1. Sort by nf_ipf in descending order.
        sorted_profiles = sorted(
            profiles_with_scores, 
            key=lambda x: x['nf_ipf'], 
            reverse=True
        )
        
        # 2. Keep the first top_n sorted items.
        top_profiles = sorted_profiles[:top_n]
        
        # 3. Extract profile strings with a list comprehension.
        final_profiles_list = [item[key_name] for item in top_profiles]
        
        # Store the processed list in a new dictionary.
        final_dict[entity_type] = final_profiles_list
        
    return final_dict



def get_keyword_dict(start_triplets, end_triplets, last_items, top_n=5):
    keyword_dict = {}
    keyword_dict = generate_keyword_dict(keyword_dict, start_triplets, "start", last_items)
    keyword_dict = generate_keyword_dict(keyword_dict, end_triplets, "end", last_items)

    keyword_dict = finalize_and_sort_profiles(keyword_dict, "keywords", top_n)
    if len(keyword_dict) > 0:
        has_sub = True
    else:
        has_sub = False
    return keyword_dict, has_sub