import fastapi
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import NoOpTracer, Tracer

from app.config import ConfigTelemetry

_TRACER: Tracer = NoOpTracer()


def setup_telemetry(app: fastapi.FastAPI, config: ConfigTelemetry) -> None:
    processor = BatchSpanProcessor(OTLPSpanExporter(endpoint=config.endpoint))

    resource = Resource(attributes={"service.name": config.service_name or ""})
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(processor)
    trace.set_tracer_provider(provider)

    global _TRACER
    _TRACER = trace.get_tracer(config.tracer_name or "")

    FastAPIInstrumentor.instrument_app(app)
    RequestsInstrumentor().instrument()


def get_tracer() -> trace.Tracer | None:
    global _TRACER
    return _TRACER
