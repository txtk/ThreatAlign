"""
Author: mjxv mjxvtxtk1@gmail.com
Date: 2025-08-10 09:39:30
LastEditors: mjxv mjxvtxtk1@gmail.com
LastEditTime: 2025-08-10 09:39:31
FilePath: /task_manage/src/config/settings/ProductionSettings.py
Description: Production settings for the application.
Copyright (c) 2025 by ${git_name_email}, All Rights Reserved.
"""

from config.settings.AppSettings import AppSettings


class ProductionSettings(AppSettings):
    """
    Production settings class that extends AppSettings.
    This class is used to manage production-specific settings.
    """

    debug: bool = False

    class Config:
        env_file = ["./envs/prod.env", "./envs/base.env"]
        env_file_encoding = "utf-8"
        validate_assignment = True
        extra = "ignore"
