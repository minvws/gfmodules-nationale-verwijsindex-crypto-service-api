import logging
from dataclasses import dataclass
from typing import Any

from app.logging.filters import LoggingStreams


@dataclass(frozen=True)
class NVIEvent:
    event_id: str
    level: int
    streams: tuple[LoggingStreams, ...]


SYS_APP_STARTED = NVIEvent("100601", logging.INFO, (LoggingStreams.APP,))
SYS_APP_STOPPED = NVIEvent("100602", logging.INFO, (LoggingStreams.APP, LoggingStreams.SIEM))
SYS_APP_CRASHED = NVIEvent("100602", logging.CRITICAL, (LoggingStreams.APP, LoggingStreams.SIEM))
SYS_UNHANDLED_EXCEPTION = NVIEvent("100604", logging.ERROR, (LoggingStreams.APP,))
SYS_CRYPTO_FAILED = NVIEvent("100606", logging.ERROR, (LoggingStreams.APP, LoggingStreams.SIEM))

PSE_EXCHANGE_FAILED = NVIEvent("900700", logging.ERROR, (LoggingStreams.APP, LoggingStreams.SIEM))
PSE_EXCHANGE_OK = NVIEvent("900701", logging.DEBUG, (LoggingStreams.APP,))

HEALTH_UNHEALTHY = NVIEvent("100600", logging.ERROR, (LoggingStreams.APP, LoggingStreams.SIEM))

# @TODO Add some extra ids in logging specs for access logging
ACCESS_REQUEST = NVIEvent("001000", logging.INFO, (LoggingStreams.APP,))


def log_event(
    logger: logging.Logger,
    event: NVIEvent,
    message: str,
    *,
    exc_info: Any = None,
    **fields: Any,
) -> None:
    extra: dict[str, Any] = {
        "event_id": event.event_id,
        "stream": list(event.streams),
    }
    extra.update(fields)
    logger.log(event.level, message, extra=extra, exc_info=exc_info)
