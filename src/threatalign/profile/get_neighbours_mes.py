import random


def json_init(input_dict, key, inital_value):
    if key not in input_dict:
        input_dict[key] = inital_value
    return input_dict


def insert_semantic_dict(entity, entity_type, neighbours_mes_dict, last_items, is_profile, profile_name):
    # Return immediately when semantic is not 1.
    if entity.get("semantic") != 1:
        return neighbours_mes_dict

    if entity_type in last_items:
        # Ensure the entity_type key exists and stores a list.
        neighbours_mes_dict = json_init(neighbours_mes_dict, entity_type, [])

        if is_profile:
            neighbour_data = {
                "name": entity.get("name"),
                "hsage": entity.get("hsage", 0),
                "profile": entity.get(profile_name, "none"),
                # "profile": entity.get("profile_without_enhance", "none"),
            }
        else:
            # Create a dictionary containing name and hsage.
            neighbour_data = {
                "name": entity.get("name"),
                "hsage": entity.get("hsage", 0),
            }

        # Append the new dictionary to the list.
        neighbours_mes_dict[entity_type].append(neighbour_data)

    return neighbours_mes_dict


def generate_neighbours_mes_dict(neighbours_mes_dict, triples, mode, last_items, is_profile, profile_name):
    for triple in triples:
        if mode == "start":
            end = triple["end"]
            end_type = end.get("entity_type")
            neighbours_mes_dict = insert_semantic_dict(
                end, end_type, neighbours_mes_dict, last_items, is_profile, profile_name
            )

        else:
            start = triple["start"]
            start_type = start.get("entity_type")
            neighbours_mes_dict = insert_semantic_dict(
                start, start_type, neighbours_mes_dict, last_items, is_profile, profile_name
            )

    return neighbours_mes_dict


def finalize_and_sort_profiles(input_dict, is_hsage, top_n=5):
    """
    Process each entity-type list in profile_dict:
    1. Sort by hsage in descending order.
    2. Keep only the first top_n items.
    3. Extract profile text so the final list contains strings only.
    """
    final_dict = {}
    for entity_type, profiles_with_scores in input_dict.items():
        random.shuffle(profiles_with_scores)
        if is_hsage:
            # 1. Sort by hsage in descending order.
            sorted_profiles = sorted(profiles_with_scores, key=lambda x: x["hsage"], reverse=True)
        else:
            sorted_profiles = profiles_with_scores

        # 2. Keep the first top_n sorted items.
        top_profiles = sorted_profiles[:top_n]
        for d in top_profiles:
            d.pop("hsage", None)
        # Store the processed list in a new dictionary.
        if len(top_profiles) > 0:
            final_dict[entity_type] = top_profiles

    return final_dict


def get_neighbours_mes_dict(
    start_triplets,
    end_triplets,
    last_items,
    top_n=5,
    is_profile: bool = True,
    is_hsage: bool = True,
    profile_name="profile",
):
    neighbours_mes_dict = {}
    neighbours_mes_dict = generate_neighbours_mes_dict(
        neighbours_mes_dict, start_triplets, "start", last_items, is_profile, profile_name
    )
    neighbours_mes_dict = generate_neighbours_mes_dict(
        neighbours_mes_dict, end_triplets, "end", last_items, is_profile, profile_name
    )

    neighbours_mes_dict = finalize_and_sort_profiles(neighbours_mes_dict, is_hsage, top_n)
    if len(neighbours_mes_dict) > 0:
        has_sub = True
    else:
        has_sub = False
    return neighbours_mes_dict, has_sub
