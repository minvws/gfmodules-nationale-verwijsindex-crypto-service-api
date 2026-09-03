import logging

from gfmodules.logging import DefaultEventCatalogue, LogEvent, LoggingStreams

_APP = LoggingStreams.APP
_SIEM = LoggingStreams.SIEM

_Base = DefaultEventCatalogue


class Log(_Base):
    SYS_APP_STARTED = _Base.SYS_APP_STARTED.replace(  # NVI-SYS-001
        event_id="100601",
        fields={
            _APP: (
                "version",
                "config_path",
                "mock_hsm",
                "telemetry_enabled",
                "stats_enabled",
            ),
        },
    )
    SYS_APP_STOPPED = _Base.SYS_APP_STOPPED.with_id("100602")  # NVI-SYS-002
    SYS_APP_CRASHED = _Base.SYS_APP_CRASHED.with_id("100602")  # NVI-SYS-002
    SYS_UNHANDLED_EXCEPTION = _Base.SYS_UNHANDLED_EXCEPTION.with_id(
        "100604"
    )  # NVI-SYS-004
    SYS_MISSING_CORRELATION_ID = _Base.SYS_MISSING_CORRELATION_ID.with_id("100606")  # NVI-SYS-006

    SYS_CRYPTO_FAILED = LogEvent("100607", logging.ERROR, (_APP, _SIEM))
    HEALTH_UNHEALTHY = LogEvent("100600", logging.ERROR, (_APP, _SIEM))

    PSE_EXCHANGE_FAILED = LogEvent("900700", logging.ERROR, (_APP, _SIEM))
    PSE_EXCHANGE_OK = LogEvent("900701", logging.DEBUG, (_APP,))
