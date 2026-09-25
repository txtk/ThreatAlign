"""
Author: mjxv mjxvtxtk1@gmail.com
Date: 2025-08-26 21:55:27
LastEditors: mjxv mjxvtxtk1@gmail.com
LastEditTime: 2025-08-27 09:34:23
FilePath: /entity_alignment/src/utils/llm_use.py
Description: LLM utility functions.
Copyright (c) 2025 by ${git_name_email}, All Rights Reserved.
"""

# from models.llm import qwen
import os
import random
import time
from traceback import format_exc

from loguru import logger
from openai import APIStatusError, RateLimitError

from config import settings

# from models.llm.glm_batch import ZhipuBatch
from models.llm import chat_mappinng
from models.llm.embedding import embedding
from models.llm.qwen3 import qwen

# zhipu = ZhipuBatch()


def get_prompt(task):
    dir_path = os.path.join(settings.prompt_dir, task)
    system_path = os.path.join(dir_path, "layer_system")
    user_path = os.path.join(dir_path, "layer_user")
    input_template_path = os.path.join(dir_path, "input_template")
    with open(system_path, "r", encoding="utf-8") as f:
        system_prompt = "".join(f.readlines())
    with open(user_path, "r", encoding="utf-8") as f:
        user_prompt = "".join(f.readlines())
    with open(input_template_path, "r", encoding="utf-8") as f:
        input_template = "".join(f.readlines())
    input_templates = input_template.split("&&*")
    return system_prompt, user_prompt, input_templates


def get_prompt_by_name(task, name):
    target_path = os.path.join(settings.prompt_dir, task, name)
    with open(target_path, "r", encoding="utf-8") as f:
        prompt = "".join(f.readlines())
    return prompt


def set_prompt(template, query):
    prompt = template.format(query)
    return prompt


def get_response(system_prompt, user_prompt):
    return qwen.send_request(system_prompt, user_prompt)


def get_response_poml(poml_content):
    models = chat_mappinng.get(settings.llm_platform)
    if models is None:
        raise RuntimeError(f"Unknown LLM platform: {settings.llm_platform}")
    if not isinstance(models, list):
        models = [models]

    last_errors = []
    max_rounds = 3
    for round_index in range(1, max_rounds + 1):
        candidates = list(models)
        random.shuffle(candidates)
        for model in candidates:
            label = getattr(model, "key_label", model.__class__.__name__)
            try:
                result = model.send_request_poml(poml_content)
                if result is None or (isinstance(result, str) and not result.strip()):
                    raise RuntimeError(f"{label} returned empty completion result")
                return result
            except RateLimitError as exc:
                last_errors.append(f"{label}: RateLimitError: {exc}")
                logger.warning("LLM request failed with rate limit on {}; trying next key.", label)
            except APIStatusError as exc:
                last_errors.append(f"{label}: APIStatusError({getattr(exc, 'status_code', 'unknown')}): {exc}")
                logger.error("LLM request failed with API status error on {}; trying next key.", label)
            except Exception as exc:
                last_errors.append(f"{label}: {exc.__class__.__name__}: {exc}")
                logger.error("LLM request failed on {}; trying next key.\n{}", label, format_exc())
        if round_index < max_rounds:
            sleep_seconds = 10 * round_index
            logger.warning(
                "All LLM keys failed in round {}/{}. Sleeping {}s before retrying.",
                round_index,
                max_rounds,
                sleep_seconds,
            )
            time.sleep(sleep_seconds)
    raise RuntimeError("All LLM keys failed after retries: " + " | ".join(last_errors[-10:]))


def get_embedding(text, dimensions=1024):
    if isinstance(text, list):
        return embedding.embed_documents(text, dimensions)
    return embedding.embed_query(text, dimensions)


# def get_zhipu_batch_chat(contexts, prompt_path):
#     zhipu.make_batch_file(prompt_path, contexts)
#     zhipu.handle_batch()
#     if zhipu.check_batch_status():
#         results = zhipu.get_batch_result()
#         return results
#     else:
#         return []
