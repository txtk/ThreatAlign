import argparse
from pathlib import Path

from loguru import logger

from config import settings
from config.mappings import rag_attck as attck_mappings
from config.mappings import rag_group as group_mappings
from config.mappings import rag_malware as malware_mappings
from utils.file.path_utils import PathUtils
from utils.vector.vector_manager import ElasticsearchVectorManager

from .prepare.prepare import pre_process


DEFAULT_DATASETS = ("heaa_random", "heaa_time")
DEFAULT_GRAPH_TYPES = ("source", "target")


def _build_rag_managers():
    return (
        ElasticsearchVectorManager(index_name="rag_malware", mappings=malware_mappings),
        ElasticsearchVectorManager(index_name="rag_attck", mappings=attck_mappings),
        ElasticsearchVectorManager(index_name="rag_group", mappings=group_mappings),
    )


def _validate_traditional_dir(dataset: str, graph_type: str) -> Path:
    traditional_dir = Path(PathUtils.path_concat(settings.dataset_dir, dataset, "traditional_save"))
    required_files = [
        traditional_dir / f"{graph_type}_attributes.json",
        traditional_dir / f"{graph_type}_entity_type_id.json",
        traditional_dir / f"{graph_type}_tuples.txt",
    ]
    missing = [str(file) for file in required_files if not file.exists()]
    if missing:
        raise FileNotFoundError(f"{dataset}/{graph_type} pre-process is missing required files: {missing}")
    return traditional_dir


def prepare_dataset_inputs(datasets: list[str], graph_types: list[str], force: bool = False) -> None:
    rag_malware, rag_attck, rag_group = _build_rag_managers()
    for dataset in datasets:
        for graph_type in graph_types:
            traditional_dir = _validate_traditional_dir(dataset, graph_type)
            logger.info(f"Starting pre-process: dataset={dataset}, graph_type={graph_type}, force={force}")
            pre_process(
                dataset,
                str(traditional_dir),
                graph_type,
                rag_malware,
                rag_attck,
                rag_group,
                force=force,
            )
            logger.info(f"Finished pre-process: dataset={dataset}, graph_type={graph_type}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare HEAA alignment inputs without profile generation.")
    parser.add_argument("--datasets", nargs="+", default=list(DEFAULT_DATASETS), choices=DEFAULT_DATASETS)
    parser.add_argument("--graph-types", nargs="+", default=list(DEFAULT_GRAPH_TYPES), choices=DEFAULT_GRAPH_TYPES)
    parser.add_argument("--force", action="store_true", help="Recompute already processed attributes and vectors.")
    args = parser.parse_args()
    prepare_dataset_inputs(args.datasets, args.graph_types, force=args.force)


if __name__ == "__main__":
    main()
