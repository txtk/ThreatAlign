from config import settings

CELERY_RESULT_URL = "redis://:{}@{}:{}/1".format(settings.redis_password, settings.redis_host, settings.redis_port)

CELERY_BROKER_URL = "amqp://{}:{}@{}:{}".format(
    settings.rabbitmq_default_user, settings.rabbitmq_default_pass, settings.rabbitmq_host, settings.rabbitmq_port
)

broker_url = [CELERY_BROKER_URL]
broker_transport_options = {"confirm_publish": True, "consumer_timeout": 7200}
worker_prefetch_multiplier = 1
result_backend = CELERY_RESULT_URL  # Celery result backend.

# time second
result_expires = 6 * 3600
timezone = "Asia/Shanghai"
task_serializer = "json"
result_serializer = "json"
accept_content = ["json"]

worker_concurrency = settings.max_connection

# task
task_track_started = True
