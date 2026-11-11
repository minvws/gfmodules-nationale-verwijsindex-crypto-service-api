from app.config import (
    Config,
    ConfigApp,
    ConfigHsmApi,
    ConfigLogging,
    ConfigPseudonym,
    ConfigStats,
    ConfigTelemetry,
    ConfigUvicorn,
)


def get_test_config() -> Config:
    return Config(
        app=ConfigApp(
            hashing_key_id="hashing-key",
            allowed_jwe_key_ids=["sk"],
        ),
        uvicorn=ConfigUvicorn(),
        telemetry=ConfigTelemetry(),
        stats=ConfigStats(),
        hsm_api=ConfigHsmApi(mock=True, url="https://hsm.test", module="m", slot="s"),
        logging=ConfigLogging(),
        pseudonym=ConfigPseudonym(
            jwks_url="https://prs.test/.well-known/jwks",
            expected_issuer="https://prs.test",
            expected_audience="oin:00000099000000001000",
        ),
    )
