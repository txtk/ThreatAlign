import asyncio

from celery import Celery, Task
from kombu import Exchange, Queue

from CeleryManage.scheduler import CeleryConfig
from CeleryManage.worker import WORKER_MAP

celery_app = Celery()
celery_app.config_from_object(CeleryConfig)

celery_app.conf.ONCE = {
    "backend": "celery_once.backends.Redis",
    "settings": {"url": CeleryConfig.CELERY_RESULT_URL, "default_timeout": 60 * 10},
}

celerybeat_schedule_tasks = dict()
# celerybeat_schedule_tasks.update()

celery_queues = (
    Queue(
        "task.result_handler",
        exchange=Exchange("task.result_handler", type="direct"),
        routing_key="task.result_handler",
    ),
    Queue(
        "task.task_creator",
        exchange=Exchange("task.task_creator", type="direct"),
        routing_key="task.task_creator",
    ),
)
router_map = {
    "task.result_handler": {"queue": "task.result_handler", "routing_key": "task.result_handler"},
    "task.task_creator": {"queue": "task.task_creator", "routing_key": "task.task_creator"},
}
imports = ["CeleryManage.scheduler.handlers"]

all_queue_workes = WORKER_MAP
for worker_name, _ in all_queue_workes.items():
    task_name = worker_name
    func_path = _["task_path"]
    imports += (func_path.rsplit(".", 1)[0],)  # type: ignore

    queue_name = task_name
    _queue = Queue(queue_name, exchange=Exchange(queue_name, type="direct"), routing_key=queue_name)
    celery_queues += (_queue,)

    router_map[task_name] = {"queue": queue_name, "routing_key": queue_name}

schedule_task_names = [_["task"] for _ in celerybeat_schedule_tasks.values()]
schedule_task_names = list(set(schedule_task_names))

for name in schedule_task_names:
    _queue = Queue(name, exchange=Exchange(name, type="direct"), routing_key=name)
    celery_queues += (_queue,)
    router_map[name] = {"queue": name, "routing_key": name}


celery_app.conf.update(
    CELERY_DEFAULT_QUEUE="task_manage",
    CELERY_QUEUES=celery_queues,
    CELERY_ROUTES=router_map,
    CELERY_IMPORTS=tuple(set(list(imports))),
    CELERYBEAT_SCHEDULE=celerybeat_schedule_tasks,
)
