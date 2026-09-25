from CeleryManage.scheduler import celery_app
from utils.llm_use import get_response_poml
import poml
import re

def properties_clean(properties: dict):
    keys_to_pop = [
        "created_time",
        "modified_time",
        "unique_id",
        "semantic",
        "importance",
        "node_type",
        "profile",
        "keywords",
        "indicator_type",
        "entity_type",
        "group_name",
        "nf_ipf"
    ]
    for key in keys_to_pop:
        if key in properties:
            properties.pop(key)
    return properties

def keyword_operate(keywords_list):
    keyword_list = []
    pattern = '"([^"]*)"'
    for i in keywords_list:
        for k, v in i.items():
            if isinstance(v, list):
                keyword_list.extend(v)
            else:
                matches = re.findall(pattern, v)
                keyword_list.extend(matches)
    return list(set(keyword_list))

@celery_app.task(name="task.threatalign.profile", ignore_result=False)
def generate_profile(entity_type, properties, keywords_list, prompt_profile_path):
    if len(keywords_list) == 0:
        has_key = False
    else:
        has_key = True
    properties = properties_clean(properties)
    context = {
        "entity_type": entity_type,
        "entity_properties": str(properties),
        "has_key": has_key,
        "keywords": keywords_list,
        "not_key": not has_key,
    }
    prompt = poml.poml(prompt_profile_path, context=context, format="openai_chat")
    result = get_response_poml(prompt)
    keyword_list = keyword_operate(keywords_list)
    if "aka_name" in properties:
        keyword_list.extend(properties["aka_name"])
    return keyword_list, result


@celery_app.task(name="task.threatalign.keyword", ignore_result=False)
def generate_keywords(profile_dict, prompt_path, target_entity_type, properties, prompt_profile_path):
    clean_properties = properties_clean(properties.copy())

    message_list = []

    for entity_type, messages in profile_dict.items():
        message_list.append({entity_type: list(set(messages))})

    # context = {
    #         "entity": str({target_entity_type:clean_properties}),
    #         "keywords": message_list,
    # }
    # prompt = poml.poml(prompt_path, context=context, format="openai_chat")
    # response = get_response_poml(prompt)
    # message_list.append({"extract_keyword": response})
    keyword_list, profile = generate_profile(target_entity_type, properties, message_list, prompt_profile_path)
    return keyword_list, profile
