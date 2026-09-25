from config.settings.AppSettings import AppSettings
from config.settings.DevelopSettings import DevelopSettings
from config.settings.ProductionSettings import ProductionSettings
from config.settings.TestSettings import TestSettings
from config.settings.base import ConfigEnum, BaseSetting

from functools import lru_cache


SETTINGS_CLASSES: dict[ConfigEnum, type[AppSettings]] = {
    ConfigEnum.prod: ProductionSettings,
    ConfigEnum.dev: DevelopSettings,
    ConfigEnum.test: TestSettings,
}


@lru_cache
def get_settings() -> AppSettings:
    """Return settings for the selected runtime mode."""
    mode = BaseSetting().mode
    return SETTINGS_CLASSES[mode]()
