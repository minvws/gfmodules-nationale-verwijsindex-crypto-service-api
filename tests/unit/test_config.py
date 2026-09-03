from gfmodules.logging import ConfigLogging

from app.config import (
    Config,
    ConfigApp,
    ConfigHsmApi,
    ConfigStats,
    ConfigTelemetry,
    ConfigUvicorn,
)


def get_test_config() -> Config:
    return Config(
        app=ConfigApp(
            hashing_key_id="hashing-key",
        ),
        uvicorn=ConfigUvicorn(),
        telemetry=ConfigTelemetry(),
        stats=ConfigStats(),
        hsm_api=ConfigHsmApi(mock=True, url="https://hsm.test", module="m", slot="s"),
        logging=ConfigLogging(),
    )
