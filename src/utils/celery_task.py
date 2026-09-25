from CeleryManage.scheduler import celery_app
import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import List, Union

import poml
from celery import signature, chain
from loguru import logger
from utils.llm_use import get_response_poml, get_embedding

def run_celery(celery_task_name: str, args_list):
    task_to_run = []
    for args in args_list:
        task = celery_app.send_task(celery_task_name, args=args)
        task_to_run.append(task)
    return task_to_run

@celery_app.task(name="task.completion", ignore_result=False)
def completion(context, prompt_path):
    prompt = poml.poml(prompt_path, context=context, format="openai_chat")
    result = get_response_poml(prompt)
    return result

@celery_app.task(name="task.embedding", ignore_result=False)
def embedding(content: Union[str, List[str]], dimensions):
    result = get_embedding(content, dimensions)
    return result


def get_completion_result_single(context, prompt_path):
    task = celery_app.send_task(
        "task.completion",
        args=(context, prompt_path),
    )
    result = task.get()
    if result is None or (isinstance(result, str) and not result.strip()):
        raise RuntimeError(f"Empty completion result, prompt={prompt_path}")
    return result


def get_completion_result_batch(contexts, prompt_path):
    args_list = [(context, prompt_path) for context in contexts]
    tasks = run_celery("task.completion", args_list)
    results = []
    for index, task in enumerate(tasks):
        result = task.get()
        if result is None or (isinstance(result, str) and not result.strip()):
            raise RuntimeError(f"Empty completion result at batch index {index}, prompt={prompt_path}")
        results.append(result)
    return results


def _load_completion_cache(cache_path: Union[str, Path]) -> dict:
    cache_path = Path(cache_path)
    if not cache_path.exists():
        return {"version": 1, "items": {}}
    with cache_path.open("r", encoding="utf-8") as handle:
        cache = json.load(handle)
    cache.setdefault("version", 1)
    cache.setdefault("items", {})
    return cache


def _save_completion_cache(cache_path: Union[str, Path], cache: dict) -> None:
    cache_path = Path(cache_path)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=cache_path.parent, delete=False, suffix=".tmp"
        ) as tmp:
            json.dump(cache, tmp, ensure_ascii=False, indent=2)
            tmp.flush()
            os.fsync(tmp.fileno())
            temp_path = Path(tmp.name)
        os.replace(temp_path, cache_path)
    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink(missing_ok=True)


def get_completion_result_batch_cached(contexts, prompt_path, cache_path, cache_keys=None):
    if cache_keys is None:
        cache_keys = [str(index) for index in range(len(contexts))]
    if len(cache_keys) != len(contexts):
        raise ValueError("cache_keys length must match contexts length")

    cache = _load_completion_cache(cache_path)
    cache["prompt_path"] = str(prompt_path)
    cache["updated_at"] = datetime.now().astimezone().isoformat()
    items = cache.setdefault("items", {})

    results = [None] * len(contexts)
    pending = []
    for index, (context, key) in enumerate(zip(contexts, cache_keys)):
        cached = items.get(key, {})
        if cached.get("status") == "done":
            result = cached.get("result")
            if result is not None and (not isinstance(result, str) or result.strip()):
                results[index] = result
                continue
        task = celery_app.send_task("task.completion", args=(context, prompt_path))
        pending.append((index, key, task))

    if pending:
        logger.info(
            "Waiting for {} uncached completion tasks; cache_path={}",
            len(pending),
            cache_path,
        )

    for index, key, task in pending:
        try:
            result = task.get()
            if result is None or (isinstance(result, str) and not result.strip()):
                raise RuntimeError(f"Empty completion result at batch index {index}, key={key}")
            items[key] = {
                "status": "done",
                "result": result,
                "updated_at": datetime.now().astimezone().isoformat(),
            }
            results[index] = result
            _save_completion_cache(cache_path, cache)
        except Exception as exc:
            items[key] = {
                "status": "error",
                "error": repr(exc),
                "updated_at": datetime.now().astimezone().isoformat(),
            }
            _save_completion_cache(cache_path, cache)
            raise

    return results


def make_chain_celery_single(celery_task_names: str, args):
    first = True
    tasks = []
    for celery_task_name in celery_task_names:
        if first:
            first = False
            task = signature(celery_task_name, args=args)
        else:
            task = signature(celery_task_name)
        tasks.append(task)
    workflow = chain(*tasks)
    result = workflow.apply_async()
    return result
        
def get_embedding_celery(content: Union[str, List[str]], dimensions: int = 1024):
    if isinstance(content, list):
        batch_size = 100
        embeddings = []
        for start in range(0, len(content), batch_size):
            batch = content[start : start + batch_size]
            task = celery_app.send_task(
                "task.embedding",
                args=(batch, dimensions),
            )
            result = task.get()
            if result is None:
                raise RuntimeError(f"Empty embedding result for batch {start // batch_size + 1}")
            if len(result) != len(batch):
                raise RuntimeError(
                    "Embedding response size mismatch for batch "
                    f"{start // batch_size + 1}: expected {len(batch)}, got {len(result)}"
                )
            embeddings.extend(result)
        return embeddings

    task = celery_app.send_task(
        "task.embedding",
        args=(content, dimensions),
    )
    result = task.get()
    return result
