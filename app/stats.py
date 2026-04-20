import time
from typing import Awaitable, Callable

import statsd
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from app.config import ConfigStats


class Stats:
    def timing(self, key: str, value: int) -> None:
        raise NotImplementedError

    def inc(self, key: str, count: int = 1, rate: int = 1) -> None:
        raise NotImplementedError

    def dec(self, key: str, count: int = 1, rate: int = 1) -> None:
        raise NotImplementedError

    def gauge(self, key: str, value: int, delta: bool = False) -> None:
        raise NotImplementedError


class NoopStats(Stats):
    def timing(self, key: str, value: int) -> None:
        """Empty method due to NoopStats implementation"""
        pass

    def inc(self, key: str, count: int = 1, rate: int = 1) -> None:
        """Empty method due to NoopStats implementation"""
        pass

    def dec(self, key: str, count: int = 1, rate: int = 1) -> None:
        """Empty method due to NoopStats implementation"""
        pass

    def gauge(self, key: str, value: int, delta: bool = False) -> None:
        """Empty method due to NoopStats implementation"""
        pass


class Statsd(Stats):
    def __init__(self, host: str, port: int):
        self.client = statsd.StatsClient(host, port)

    def timing(self, key: str, value: int) -> None:
        self.client.timing(key, value)

    def inc(self, key: str, count: int = 1, rate: int = 1) -> None:
        self.client.incr(key, count, rate)

    def dec(self, key: str, count: int = 1, rate: int = 1) -> None:
        self.client.decr(key, count, rate)

    def gauge(self, key: str, value: int, delta: bool = False) -> None:
        self.client.gauge(key, value, delta)


_STATS: Stats = NoopStats()


def setup_stats(config: ConfigStats) -> None:
    if config.enabled is False:
        return

    config.host = config.host or "localhost"
    config.port = config.port or 8125

    global _STATS
    _STATS = Statsd(config.host, config.port)


def get_stats() -> Stats:
    global _STATS
    return _STATS


class StatsdMiddleware(BaseHTTPMiddleware):
    """
    Middleware to record request info and response time for each request
    """

    def __init__(self, app: ASGIApp, module_name: str):
        super().__init__(app)
        self.module_name = module_name

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        key = f"{self.module_name}.http.request.{request.method.lower()}.{request.url.path}"
        get_stats().inc(key)

        start_time = time.monotonic()
        response = await call_next(request)
        end_time = time.monotonic()

        response_time = int((end_time - start_time) * 1000)
        get_stats().timing(f"{self.module_name}.http.response_time", response_time)

        return response
