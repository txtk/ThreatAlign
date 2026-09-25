from typing import Any, Dict, Optional
from uuid import NAMESPACE_DNS, uuid5

from elasticsearch import helpers
from elasticsearch.helpers import BulkIndexError
from loguru import logger

from config import elastic

from .query_builders import KNNQueryBuilder, TermsQueryBuilder
from .RRF import RRF


class ElasticsearchVectorManager:
    def __init__(self, index_name: str, mappings: dict, vector_dimensions: int = 1024, num_results: int = 10):
        """Manage one Elasticsearch vector index used by ThreatAlign."""
        self.index_name = index_name
        self.vector_dimensions = vector_dimensions
        self.num_results = num_results

        self.es_client = elastic
        self.mappings = mappings
        if not self.es_client.ping():
            raise ConnectionError("Cannot connect to Elasticsearch; check the configuration.")

    def get_insert_action(self, docs: list):
        actions = []
        for doc in docs:
            doc_id = doc.get("_id")

            if doc_id is None or doc_id == "":
                name_for_id = str(doc.get("name", "")).lower()
                identifier = f"{name_for_id}_{doc.get('raw_content', '')}"
                doc_id = str(uuid5(NAMESPACE_DNS, identifier))

            source = doc.copy()
            if "_id" in source:
                del source["_id"]

            actions.append(
                {
                    "_id": doc_id,
                    "_index": self.index_name,
                    "_op_type": "index",
                    "_source": source,
                }
            )
        return actions

    def index_document(self, docs: list) -> Dict[str, Any]:
        actions = self.get_insert_action(docs)
        try:
            success = 0
            failed = 0
            for ok, item in helpers.parallel_bulk(
                self.es_client,
                actions,
                thread_count=4,
                chunk_size=500,
                queue_size=4,
            ):
                if ok:
                    success += 1
                else:
                    failed += 1
                    if failed <= 5:
                        logger.info(f"Failed to index document: {item}")
            logger.info(f"Successfully indexed {success} documents.")
            if failed:
                logger.info(f"Failed to index {failed} documents.")
        except BulkIndexError as e:
            for i, error_info in enumerate(e.errors[:5]):
                logger.info(f"\n--- Error {i + 1} ---")
                action, result = next(iter(error_info.items()))
                logger.info(f"Action type: {action}")
                logger.info(f"Document ID (_id): {result.get('_id')}")
                logger.info(f"Index (_index): {result.get('_index')}")
                logger.info(f"Failure reason: {result.get('error', {}).get('reason')}")
                logger.info(f"Failure type: {result.get('error', {}).get('type')}")
                if "caused_by" in result.get("error", {}):
                    logger.info(f"Root cause (caused_by): {result['error']['caused_by']}")

    def build_query_hybrid(self, retrievers):
        rrf = RRF()
        rrf.add_retrievers(retrievers)
        return rrf.get_query()

    def build_query_terms(self, field: str, values: list):
        builder = TermsQueryBuilder(field, values)
        return builder.get_query()

    def build_query_knn(self, vector_field: str, query_vector: list, k: int = 10, num_candidates: int = 100):
        builder = KNNQueryBuilder(vector_field, query_vector, k, num_candidates)
        return builder.get_query()

    def perform_search(self, query, top_k=None):
        if top_k is None:
            top_k = self.num_results
        response = self.es_client.search(index=self.index_name, body=query, size=top_k)
        return response["hits"]["hits"]

    def perform_search_detailed(self, query, top_k=None):
        """Run a query and return normalized hits plus the total hit count."""
        if top_k is None:
            top_k = self.num_results
        response = self.es_client.search(index=self.index_name, body=query, size=top_k)
        hits = response["hits"]["hits"]
        total_hits = response["hits"]["total"]["value"]

        results = []
        for hit in hits:
            source = hit["_source"]
            source["_id"] = hit["_id"]
            source["_score"] = hit["_score"]
            results.append(source)

        return results, total_hits

    def get_index_mapping(self):
        """Return the mapping for this Elasticsearch index."""
        mapping = self.es_client.indices.get_mapping(index=self.index_name)
        mapping = mapping.get(self.index_name)
        return mapping["mappings"]

    def index_exists(self, index_name: Optional[str] = None) -> bool:
        """Return whether an Elasticsearch index exists."""
        idx = index_name or self.index_name
        try:
            return self.es_client.indices.exists(index=idx)
        except Exception as e:
            logger.exception(f"Error while checking index existence: {idx} - {e}")
            return False

    def delete_index(self):
        """Delete this Elasticsearch index if it exists."""
        response = self.es_client.indices.delete(index=self.index_name, ignore_unavailable=True)
        return bool(response.get("acknowledged"))

    def create_index(self, settings: dict = None):
        """Create this Elasticsearch index with the configured mappings."""
        if self.es_client.indices.exists(index=self.index_name):
            logger.info(f"Index '{self.index_name}' already exists; no creation needed.")
            return False

        response = self.es_client.indices.create(index=self.index_name, mappings=self.mappings, settings=settings)

        if response.get("acknowledged"):
            logger.info(f"Index '{self.index_name}' created successfully.")
            return True

        logger.info(f"Index '{self.index_name}' failed to create.")
        return False

    def recreate_index(self, settings: dict = None):
        """Delete and recreate this Elasticsearch index."""
        self.delete_index()
        return self.create_index(settings)

    def count_documents(self) -> int:
        """Count documents in this Elasticsearch index."""
        try:
            response = self.es_client.count(index=self.index_name)
            return response["count"]
        except Exception as e:
            logger.error(f"Error while counting index documents: {self.index_name} - {e}")
            return 0
