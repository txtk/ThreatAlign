def is_profile_like_key(key: str) -> bool:
    return (
        key == "profile"
        or key.startswith("profile_")
        or key.startswith("profile_without")
        or key.endswith("_profile")
        or "_profile_" in key
    )


def filter_self_info(entity, is_enhance, ignore_list):
    mes = {}
    for i in entity:
        if i in ignore_list:
            continue
        if is_profile_like_key(i):
            continue
        if not is_enhance:
            if i.find("uncertain_") != -1:
                continue
        mes[i] = entity[i]
    return mes
