"""
Author: mjxv mjxvtxtk1@gmail.com
Date: 2025-08-10 09:36:40
LastEditors: mjxv mjxvtxtk1@gmail.com
LastEditTime: 2025-08-10 09:38:34
FilePath: /task_manage/src/config/settings/DevelopSettings.py
Description: develop settings for the application.
Copyright (c) 2025 by ${git_name_email}, All Rights Reserved.
"""

from config.settings.AppSettings import AppSettings


class DevelopSettings(AppSettings):
    """
    Development settings class that extends AppSettings.
    This class is used to manage development-specific settings.
    """

    debug: bool = True

    class Config:
        env_file = ["./envs/dev.env", "./envs/base.env"]
        env_file_encoding = "utf-8"
        extra = "ignore"
