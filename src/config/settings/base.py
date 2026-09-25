"""
Author: mjxv mjxvtxtk1@gmail.com
Date: 2025-08-10 09:26:06
LastEditors: mjxv mjxvtxtk1@gmail.com
LastEditTime: 2025-08-10 09:38:50
FilePath: /task_manage/src/config/settings/base.py
Description: Base settings for the application and its runtime mode.
Copyright (c) 2025 by ${git_name_email}, All Rights Reserved.
"""

from enum import Enum

from pydantic_settings import BaseSettings


class ConfigEnum(Enum):
    prod = "prod"
    dev = "dev"
    test = "test"


class BaseSetting(BaseSettings):
    """
    Base settings class for the application.
    Inherits from BaseSettings to utilize Pydantic's settings management.
    """

    mode: ConfigEnum = ConfigEnum.prod

    class Config:
        env_file = "./envs/.env"
        env_file_encoding = "utf-8"
        extra = "ignore"
