# Log events

<!-- markdownlint-disable MD013 -->

Generated from `app.logging.events:Log` by `gfmodules.logging.event_overview`.
Do not edit by hand.

Each stream lists the events that reach it and the fields they carry there besides the context fields.
*any* means the event has no allow-list, so every field it is logged with reaches the stream.
*none* means the event carries only the context fields there.

## Context fields

Every event carries these on every stream, whenever the request context holds a value for them.

- `request_id`
- `ip`
- `user_agent`
- `client_trace_id`
- `correlation_id`
- `endpoint`
- `method`
- `scope`

## Stream `app`

| Event | Id | Level | Fields |
| --- | --- | --- | --- |
| `SYS_APP_STARTED` | 100601 | INFO | `version`, `config_path`, `mock_hsm`, `telemetry_enabled`, `stats_enabled`, `test_endpoints_enabled` |
| `SYS_APP_STOPPED` | 100602 | INFO | `shutdown_reason`, `last_exception_type` |
| `SYS_APP_CRASHED` | 100602 | CRITICAL | `shutdown_reason`, `last_exception_type` |
| `SYS_UNHANDLED_EXCEPTION` | 100604 | ERROR | `exception_type`, `endpoint`, `method` |
| `SYS_MISSING_CORRELATION_ID` | 100606 | ERROR | `endpoint`, `method` |
| `SYS_CRYPTO_FAILED` | 100607 | ERROR | `error_type` |
| `HEALTH_UNHEALTHY` | 100600 | ERROR | `component`, `status`, `error_detail` |
| `PSE_EXCHANGE_FAILED` | 900700 | ERROR | `error_type` |
| `PSE_EXCHANGE_OK` | 900701 | INFO | *none* |
| `ACCESS_REQUEST` | 100 | INFO | `endpoint`, `method`, `status_code`, `status_code_missing`, `duration_ms`, `body`, `body_truncated` |

## Stream `siem`

| Event | Id | Level | Fields |
| --- | --- | --- | --- |
| `SYS_APP_STOPPED` | 100602 | INFO | `shutdown_reason` |
| `SYS_APP_CRASHED` | 100602 | CRITICAL | `shutdown_reason` |
| `SYS_UNHANDLED_EXCEPTION` | 100604 | ERROR | `exception_type`, `endpoint`, `method` |
| `SYS_CRYPTO_FAILED` | 100607 | ERROR | `error_type` |
| `HEALTH_UNHEALTHY` | 100600 | ERROR | `component`, `status` |
| `PSE_EXCHANGE_FAILED` | 900700 | ERROR | `error_type` |
