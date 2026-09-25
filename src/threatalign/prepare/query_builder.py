from typing import Any, List

from utils.vector.query_builders import (
    BoolQueryBuilder,
    ExistsQueryBuilder,
    KNNQueryBuilder,
    MatchQueryBuilder,
    TermQueryBuilder,
    TermsQueryBuilder,
)


class QueryBuilder:
    # Priority configuration: field name -> weight.
    PRIORITY_BOOSTS = {"related_groups": 0.1, "related_malwares": 0.1, "related_attcks": 0.1}

    def _apply_priority_boosts(self, bool_builder: BoolQueryBuilder):
        """Apply predefined priority boosts to the query."""
        for field, boost in self.PRIORITY_BOOSTS.items():
            bool_builder.add_should(ExistsQueryBuilder(field, boost=boost))
        return bool_builder

    def build_match_query(self, field_name: str, content: str, priority: bool = True):
        """Build a full-text match query."""
        bool_builder = BoolQueryBuilder()
        bool_builder.add_must(MatchQueryBuilder(field=field_name, query=content))

        if priority:
            self._apply_priority_boosts(bool_builder)

        return bool_builder.get_query()

    def build_term_query(self, field_name: str, value: Any, priority: bool = True):
        """Build an exact-match query for one value."""
        bool_builder = BoolQueryBuilder()
        bool_builder.add_must(TermQueryBuilder(field=field_name, value=value))

        if priority:
            self._apply_priority_boosts(bool_builder)

        return bool_builder.get_query()

    def build_terms_query(self, field_name: str, values: List[Any], priority: bool = True):
        """Build an exact-match query for multiple values."""
        bool_builder = BoolQueryBuilder()
        bool_builder.add_must(TermsQueryBuilder(field=field_name, values=values))

        if priority:
            self._apply_priority_boosts(bool_builder)

        return bool_builder.get_query()

    def build_knn_query(self, vector_field: str, query_vector: List[float], k: int = 10, num_candidates: int = 100, priority: bool = True):
        """Build a vector query."""
        bool_builder = BoolQueryBuilder()
        bool_builder.add_must(KNNQueryBuilder(vector_field, query_vector, k, num_candidates))
        if priority:
            self._apply_priority_boosts(bool_builder)
        return bool_builder.get_query()