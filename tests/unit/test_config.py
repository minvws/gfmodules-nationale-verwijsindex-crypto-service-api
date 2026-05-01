

from app.config import Config, ConfigApp, ConfigHsmApi, ConfigLogging, ConfigPseudonymApi, ConfigStats, ConfigTelemetry, ConfigUvicorn


def get_test_config() -> Config:
    return Config(
        app=ConfigApp(
            nvi_ura_number="12345678",
            key_id="signing-key",
            hashing_key_id="hashing-key",
        ),
        uvicorn=ConfigUvicorn(),
        telemetry=ConfigTelemetry(),
        stats=ConfigStats(),
        pseudonym_api=ConfigPseudonymApi(endpoint="https://example.com/prs"),
        hsm_api=ConfigHsmApi(
            mock=True, url="https://hsm.test", module="m", slot="s"
        ),
        logging=ConfigLogging(),
    )