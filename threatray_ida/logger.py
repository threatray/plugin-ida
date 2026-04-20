import logging

LOGGING_LEVEL = logging.INFO

LOGGING_FORMAT: str = '%(asctime)s %(levelname)s:%(name)s:%(message)s'
if LOGGING_LEVEL == logging.DEBUG:
    LOGGING_FORMAT = '%(asctime)s %(levelname)s:%(name)s:%(filename)s:L%(lineno)d:%(message)s'

logging.basicConfig(
    level=LOGGING_LEVEL,
    format=LOGGING_FORMAT
)


def get_log(name: str = 'plugin.threatray'):
    return logging.getLogger(name)
