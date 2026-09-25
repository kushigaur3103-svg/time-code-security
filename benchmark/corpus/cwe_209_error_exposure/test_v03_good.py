import logging

logger = logging.getLogger(__name__)

def handle():
    try:
        return load()
    except Exception as e:
        logger.error("handled %s", e)
        return "Server error"
