"""
Author: mjxv mjxvtxtk1@gmail.com
Date: 2025-08-10 12:47:47
LastEditors: mjxv mjxvtxtk1@gmail.com
LastEditTime: 2025-08-10 13:02:28
FilePath: /task_manage/src/CeleryManage/scheduler/handlers.py
Description: Celery task handlers, including task creation and result handling.
Copyright (c) 2025 by ${git_name_email}, All Rights Reserved.
"""

import asyncio
import datetime
import time
import uuid

from celery import signature
from celery_once import QueueOnce
from loguru import logger

from CeleryManage.scheduler import celery_app
from CeleryManage.worker import WORKER_MAP
from models.database.postgre.TaskModel import TaskModel


@celery_app.task(base=QueueOnce, once={"graceful": True}, name="task.task_creator")
def task_creator(work_name: str, end_status: int, *args):
    @logger.catch
    async def _task_creator(worker_name: str, end_status: int, args: tuple):
        safe_args = args if args else ()
        record_id = uuid.uuid5(uuid.NAMESPACE_DNS, str(time.time()))
        safe_args = (str(record_id),) + safe_args
        result = celery_app.send_task(
            worker_name,
            args=safe_args,
            chain=[signature("task.result_handler", args=(worker_name, str(record_id), end_status))],
        )
        await TaskModel.aio_create(id=record_id, worker=worker_name, args=args, task_id=result.id)
        logger.info(f"[Task Creator]Create task {worker_name}-{record_id}.")
        return {"record_id": str(record_id)}

    safe_args = args if args else ()
    logger.info("[Task Creator]Start running...")
    loop = asyncio.get_event_loop()
    task = loop.create_task(_task_creator(work_name, end_status, safe_args))
    loop.run_until_complete(task)
    return task.result()


@celery_app.task(base=QueueOnce, once={"graceful": True}, name="task.result_handler", ignore_result=True)
def task_result_handler(result_data: dict, worker_name: str, record_id: str, status: int):
    @logger.catch
    async def _result_handler(result_data: dict, worker_name: str, record_id: str, status: int):
        # TODO: add retry-state handling.
        if not result_data:
            result_data = {}

        if status == 10:  # If the task chain has ended, call the result handler; otherwise only update status.
            result_handler = WORKER_MAP.get(worker_name, {}).get("result_handler")
            logger.info("[Result Handler]Status is 10, run result_handler and save result...")
            if not result_handler:
                logger.error(f"[Result Handler]Get worker<{worker_name}>result handler fail.")
                result_data = {"error": "result handler not exists", "result": result_data}
            else:
                result_data = await result_handler(result_data)

        _task, _ = await TaskModel.aio_get_or_create(id=record_id, worker=worker_name)
        _task.result = result_data
        _task.status = status
        if status == 10:
            _task.finishTime = datetime.datetime.now()
        else:
            _task.updateTime = datetime.datetime.now()

        await _task.aio_save()
        logger.info(f"[Result Handler]Complete handler {worker_name}-{record_id}, new status: {status}.")

    logger.info(f"[Result Handler]Start handler {worker_name}-{record_id}...")
    loop = asyncio.get_event_loop()
    loop.run_until_complete(_result_handler(result_data, worker_name, record_id, status))
