from app.config import (
    Config,
    ConfigApp,
    ConfigHsmApi,
    ConfigLogging,
    ConfigStats,
    ConfigTelemetry,
    ConfigUvicorn,
)


def get_test_config() -> Config:
    return Config(
        app=ConfigApp(
            nvi_ura_number="12345678",
            hashing_key_id="hashing-key",
            aes_key_id="aes-key-id",
        ),
        uvicorn=ConfigUvicorn(),
        telemetry=ConfigTelemetry(),
        stats=ConfigStats(),
        hsm_api=ConfigHsmApi(mock=True, url="https://hsm.test", module="m", slot="s"),
        logging=ConfigLogging(),
    )
