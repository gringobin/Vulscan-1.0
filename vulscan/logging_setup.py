# vulscan/logging_setup.py
import logging
from typing import Optional

def configure_logging(level: int = logging.INFO, fmt: Optional[str] = None):
    logger = logging.getLogger("vulscan")
    # Remove all handlers (idempotent)
    for h in list(logger.handlers):
        logger.removeHandler(h)

    logger.setLevel(level)
    handler = logging.StreamHandler()
    if not fmt:
        fmt = "%(asctime)s %(levelname)s %(name)s: %(message)s"
    formatter = logging.Formatter(fmt)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Reduce verbosity for noisy libraries unless debug
    if level > logging.DEBUG:
        logging.getLogger("asyncio").setLevel(logging.WARNING)
        logging.getLogger("aiohttp").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)

    return logger
