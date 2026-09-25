from typing import Any, List


class TermsQueryBuilder:
    def __init__(self, field: str, values: List[Any]):
        self.query = {"query": {"terms": {field: values}}}

    def get_query(self):
        return self.query


class TermQueryBuilder:
    def __init__(self, field: str, value: Any):
        self.query = {"query": {"term": {field: value}}}

    def get_query(self):
        return self.query


class MatchQueryBuilder:
    def __init__(self, field: str, query: str):
        self.query = {"query": {"match": {field: query}}}

    def get_query(self):
        return self.query


class KNNQueryBuilder:
    def __init__(self, vector_field: str, query_vector: List[float], k: int = 10, num_candidates: int = 100):
        self.query = {
            "knn": {"field": vector_field, "query_vector": query_vector, "k": k, "num_candidates": num_candidates}
        }

    def get_query(self):
        return self.query


class ExistsQueryBuilder:
    def __init__(self, field: str, boost: float = 1.0):
        self.query = {"exists": {"field": field, "boost": boost}}

    def get_query(self):
        # Return a query fragment that can be nested inside a bool query.
        return self.query


class BoolQueryBuilder:
    def __init__(self):
        self.query = {"query": {"bool": {"must": [], "should": [], "filter": []}}}

    def add_must(self, sub_query: Any):
        # If a builder object is passed, call get_query().
        q = sub_query.get_query() if hasattr(sub_query, "get_query") else sub_query
        # Remove the outer "query" wrapper for nesting.
        if "query" in q:
            q = q["query"]
        self.query["query"]["bool"]["must"].append(q)
        return self

    def add_should(self, sub_query: Any):
        q = sub_query.get_query() if hasattr(sub_query, "get_query") else sub_query
        if "query" in q:
            q = q["query"]
        self.query["query"]["bool"]["should"].append(q)
        return self

    def add_filter(self, sub_query: Any):
        q = sub_query.get_query() if hasattr(sub_query, "get_query") else sub_query
        if "query" in q:
            q = q["query"]
        self.query["query"]["bool"]["filter"].append(q)
        return self

    def get_query(self):
        return self.query
