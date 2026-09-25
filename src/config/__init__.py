from elasticsearch import Elasticsearch
import poml

from config.config import get_settings


settings = get_settings()
elastic = Elasticsearch(settings.elastic_url, api_key=settings.elastic_api or None, request_timeout=30)
poml.set_trace(False, trace_dir=settings.poml_log_dir)


profile_mode = [
    # (True, False, True, True, 0, "profile_without_enhance_0"),
    # (True, False, True, False, 0, "profile_without_enhance_0_no_hsage"),
    # (True, False, True, True, 20, "profile_without_enhance_20"),
    # (True, False, True, False, 20, "profile_without_enhance_20_no_hsage"),
    # (True, False, True, False, 15, "profile_without_enhance_15_no_hsage"),
    # (True, False, True, True, 15, "profile_without_enhance_15"),
    # (True, False, True, True, 10, "profile_without_enhance"),
    # (True, False, True, False, 10, "profile_without_enhance_10_no_hsage"),
    # (False, False, True, True, 5, "profile_without_enhance_5_without_profile"),
    # (True, False, False, True, 5, "profile_without_enhance_5_without_retriver"),
    # (False, False, False, True, 5, "profile_without_enhance_5_without_profile_retriver"),
    (True, False, True, True, 5, "profile_without_enhance_5"),
    # (True, False, True, False, 5, "profile_without_enhance_5_no_hsage"),
    # (True, False, True, True, 1, "profile_without_enhance_1"),
    # (True, False, True, False, 1, "profile_without_enhance_1_no_hsage"),
    
]


match_mode_test = [
    (True, True, "profile"),
    (True, True, "profile_without_neighbour"),
    (True, True, "profile_without_enhance"),
    (True, True, "profile_without_retriver"),
]

match_mode_heaa = [
    # (True, True, "profile_without_enhance_20", 10),
    # (True, True, "profile_without_enhance_20_no_hsage", 10),
    # (True, True, "profile_without_enhance_15", 10),
    # (True, True, "profile_without_enhance_15_no_hsage", 10),
    # (True, True, "profile_without_enhance", 10),
    # (True, True, "profile_without_enhance_10_no_hsage", 10),
    # (True, True, "profile_without_enhance_5", 10),
    # (True, True, "profile_without_enhance_5_no_hsage", 10),
    # (True, True, "profile_without_enhance_1", 10),
    # (True, True, "profile_without_enhance_1_no_hsage", 10),
    # (True, True, "profile_without_enhance_0", 10),
    # (True, True, "profile_without_enhance_0_no_hsage", 10),


    (True, True, "profile_without_enhance_5", 10),
    # (True, True, "profile_without_enhance_5_without_profile", 10),
    # (True, True, "profile_without_enhance_5_without_retriver", 10),
    # (False, True, "profile_without_enhance_5", 10),
    # (True, False, "profile_without_enhance_5", 10),
    # (False, False, "profile_without_enhance_5", 10),
    # (False, False, "profile_without_enhance_5_without_retriver", 10),
    # (False, False, "profile_without_enhance_5_without_profile_retriver", 10),
]


base_ignore_properties = [
    "no_semantic_neighbors",
    "unique_id",
    "processed",
    "valid_until",
    "label_description",
    "created_time",
    "nf_ipf",
    "x_mitre_description",
    "latitude",
    "semantic",
    "description",
    "standard_attck_name",
    "standard_attck_id",
    "hsage",
    "gid",
    "longitude",
    "group_name",
    "modified_time",
    "valid_from",
    "profile",
    "profile_without_enhance",
    "profile_without_neighbour",
    "profile_without_retriver",
    "profile_without_enhance_15",
    "profile_without_enhance_15_no_hsage",
    "profile_without_enhance_20",
    "profile_without_enhance_20_no_hsage",
    "profile_without_enhance",
    "profile_without_enhance_10_no_hsage",
    "profile_without_enhance_5",
    "profile_without_enhance_5_no_hsage",
    "profile_without_enhance_1",
    "profile_without_enhance_1_no_hsage",
    "profile_without_enhance_0",
    "profile_without_enhance_0_no_hsage",
    "profile_without_enhance_5_without_profile",
    "profile_without_enhance_5_without_retriver",
    "profile_without_enhance_5_without_profile_retriver"
]

heaa_ignore_properties = base_ignore_properties + [
    "aka_name",
    "label_masked",
    "query_unit",
    "source_report",
    "source_report_id",
    "source_report_stem",
]

ignore_dict = {
    "heaa_random": heaa_ignore_properties,
    "heaa_time": heaa_ignore_properties,
}
