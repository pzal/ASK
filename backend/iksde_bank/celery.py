import os
from celery import Celery

# set the default Django settings module for the 'celery' program.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "iksde_bank.settings")

app = Celery("iksde_bank")

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
# - namespace='CELERY' means all celery-related configuration keys
#   should have a `CELERY_` prefix.
app.config_from_object("django.conf:settings", namespace="CELERY")

app.conf.task_routes = {
    "transfers.tasks.*": {"queue": "transfers"},
}

# Load task modules from all registered Django app configs.
app.autodiscover_tasks()
