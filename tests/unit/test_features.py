from app.config import Config
from app.features import FEATURES, enabled_features
from tests.unit.test_config import get_test_config


def _config(mock: bool) -> Config:
    config = get_test_config()
    config.hsm_api.mock = mock
    return config


def _ids(config: Config) -> list[str]:
    return [feature.id for feature in enabled_features(config)]


def test_all_features_enabled_with_hsm() -> None:
    assert _ids(_config(mock=False)) == [feature.info.id for feature in FEATURES]


def test_hsm_feature_follows_mock_flag() -> None:
    assert "hsm" in _ids(_config(mock=False))
    assert "hsm" not in _ids(_config(mock=True))


def test_feature_ids_are_unique() -> None:
    ids = [feature.info.id for feature in FEATURES]

    assert len(ids) == len(set(ids))
