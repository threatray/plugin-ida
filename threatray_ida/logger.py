import logging

LOGGING_LEVEL = logging.INFO

LOGGING_FORMAT: str = '%(asctime)s %(levelname)s:%(name)s:%(message)s'
if LOGGING_LEVEL == logging.DEBUG:
    LOGGING_FORMAT = '%(asctime)s %(levelname)s:%(name)s:%(filename)s:L%(lineno)d:%(message)s'

BASE_LOGGER_NAME: str = 'plugin.threatray'

# IDA runs every plugin in one interpreter: configuring the root logger would change logging for all of them.
_base_logger = logging.getLogger(BASE_LOGGER_NAME)
if not _base_logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter(LOGGING_FORMAT))
    _base_logger.addHandler(_handler)
    _base_logger.setLevel(LOGGING_LEVEL)
    _base_logger.propagate = False


def get_log(name: str = BASE_LOGGER_NAME):
    if name != BASE_LOGGER_NAME and not name.startswith(f'{BASE_LOGGER_NAME}.'):
        name = f'{BASE_LOGGER_NAME}.{name}'
    return logging.getLogger(name)
