from iksde_bank.celery import app as celery
from utils.logging import log


@celery.task()
def debug_task():
    log("Running debug task…")
