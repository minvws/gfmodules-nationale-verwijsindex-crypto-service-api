from contextvars import ContextVar

UNSET = "-"

REQUEST_ID_HEADER = "X-Request-ID"
CLIENT_TRACE_ID_HEADER = "X-Client-Trace-ID"
CORRELATION_ID_HEADER = "X-GF-Correlation-ID"

request_id_var: ContextVar[str] = ContextVar("request_id", default=UNSET)
ip_var: ContextVar[str] = ContextVar("ip", default=UNSET)
client_trace_id_var: ContextVar[str] = ContextVar("client_trace_id", default=UNSET)
endpoint_var: ContextVar[str] = ContextVar("endpoint", default=UNSET)
method_var: ContextVar[str] = ContextVar("method", default=UNSET)
correlation_id_var: ContextVar[str] = ContextVar("correlation_id", default=UNSET)
