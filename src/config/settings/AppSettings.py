import logging
import sys

from loguru import logger

from config.settings.base import BaseSettings
from utils.logging import InterceptHandler


class AppSettings(BaseSettings):
    """Runtime settings required by the public ThreatAlign experiment code."""

    redis_host: str = ""
    redis_port: int = 6379
    redis_password: str = ""

    rabbitmq_host: str = ""
    rabbitmq_port: int = 5672
    rabbitmq_default_user: str = ""
    rabbitmq_default_pass: str = ""

    elastic_url: str = ""
    elastic_api: str = ""

    max_connection: int = 4

    json_dir: str = "data/raw_data/json"
    prompt_dir: str = "data/prompt"
    dataset_dir: str = "data/dataset"
    poml_log_dir: str = "data/log/poml"
    result_log_dir: str = "data/log/test"

    base_url_em: str = "https://api.siliconflow.cn/v1"
    base_url_chat: str = ""
    api_key_chat: str = ""
    qwen_qa: str = "Qwen/Qwen3-Embedding-8B"
    embedding: str = "Qwen/Qwen3-Embedding-8B"
    embedding_dimension_rag: int = 1024
    embedding_dimension_att: int = 4096
    max_tokens: int = 4096
    rerank: str = "bge-reranker-large"
    temperature: float = 0.3

    zhipu_api_key: str = ""
    zhipu_model_name: str = "glm-4.5-air"
    zhipu_url: str = "https://open.bigmodel.cn/api/paas/v4"

    xm_url: str = "https://api.xiaomimimo.com/v1"
    xm_api_key: str = ""
    xm_model_name: str = "mimo-v2-flash"

    ds_url: str = "https://api.deepseek.com"
    ds_api_key: str = ""
    ds_model_name: str = "deepseek-chat"

    sc_url: str = "https://api.siliconflow.cn/v1"
    sc_api_key: list[str] = []
    sc_model_name: str = "deepseek-ai/DeepSeek-V3.2"

    llm_platform: str = "sc"
    test_mode_vector_match: str = "hybrid"

    loggers: tuple[str, str] = ("uvicorn.asgi", "uvicorn.access")
    log_level: str = "INFO"

    def configure_logging(self):
        logging.getLogger().handlers = [InterceptHandler]
        for logger_name in self.loggers:
            logging.getLogger(logger_name).handlers = [InterceptHandler]
            logging.getLogger(logger_name).setLevel(self.log_level)
        logger.configure(handlers=[{"sink": sys.stderr, "level": self.log_level}])

    class Config:
        env_file = ".envs/base.env"
        env_file_encoding = "utf-8"
        extra = "ignore"
