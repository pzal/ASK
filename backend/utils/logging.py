import logging
import sys

logger = logging.getLogger("logstash-logger")


def log(msg, extra=None):
    logger.info(msg, extra=extra)


def error(msg, extra=None):
    logger.error(msg, extra=extra)


def exception(msg, exc_info, extra=None):
    logger.exception(msg, extra=extra, exc_info=exc_info)
