from typing import List
import random
import time

from openai import APIError, OpenAI
from loguru import logger

from config import settings


class Embedding:
    def __init__(self):
        self.clients = [
            (f"silicon_key_{index + 1}", OpenAI(base_url=settings.base_url_em, api_key=api_key))
            for index, api_key in enumerate(settings.sc_api_key)
        ]

    def _client_order(self):
        clients = list(self.clients)
        random.shuffle(clients)
        return clients

    def _create_embeddings(self, input_data, dimensions):
        last_errors = []
        max_rounds = 3
        for round_index in range(1, max_rounds + 1):
            for label, client in self._client_order():
                try:
                    response = client.embeddings.create(
                        model=settings.embedding,
                        input=input_data,
                        dimensions=dimensions,
                    )
                    return [item.embedding for item in response.data]
                except APIError as exc:
                    last_errors.append(f"{label}: APIError: {exc}")
                    logger.error("Embedding request failed on {}; trying next key.", label)
                except Exception as exc:
                    last_errors.append(f"{label}: {exc.__class__.__name__}: {exc}")
                    logger.exception("Embedding request failed on {}; trying next key.", label)
            if round_index < max_rounds:
                sleep_seconds = 10 * round_index
                logger.warning(
                    "All embedding keys failed in round {}/{}. Sleeping {}s before retrying.",
                    round_index,
                    max_rounds,
                    sleep_seconds,
                )
                time.sleep(sleep_seconds)
        raise RuntimeError("All embedding keys failed after retries: " + " | ".join(last_errors[-10:]))

    def embed_query(self, text: str, dimensions) -> List[float]:
        """
        Generate an embedding vector for a single query string.

        Args:
            text (str): Single query string to embed.

        Returns:
            List[float]: Embedding vector for the query string.
        """
        if not isinstance(text, str):
            print("Invalid input: ", text)
            raise TypeError("Input must be a string.")

        return self._create_embeddings([text], dimensions)[0]

    def embed_documents(self, texts: List[str], dimensions) -> List[List[float]]:
        """
        Generate embeddings for multiple texts with batching (up to 100 per batch).

        Args:
            texts (List[str]): Texts to embed.

        Returns:
            List[List[float]]: Embedding vectors for the input texts.
        """
        if not isinstance(texts, list):
            raise TypeError("Input must be a list.")

        batch_size = 100
        all_embeddings = []

        for i in range(0, len(texts), batch_size):
            batch = texts[i : i + batch_size]
            batch_embeddings = self._create_embeddings(batch, dimensions)
            if len(batch_embeddings) != len(batch):
                raise RuntimeError(
                    f"Embedding response size mismatch: expected {len(batch)}, got {len(batch_embeddings)}"
                )
            all_embeddings.extend(batch_embeddings)

        return all_embeddings


embedding = Embedding()
