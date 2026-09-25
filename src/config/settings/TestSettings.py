"""
Author: mjxv mjxvtxtk1@gmail.com
Date: 2025-08-10 09:40:32
LastEditors: mjxv mjxvtxtk1@gmail.com
LastEditTime: 2025-08-10 09:42:27
FilePath: /task_manage/src/config/settings/TestSettings.py
Description: Test settings for the application.
Copyright (c) 2025 by ${git_name_email}, All Rights Reserved.
"""

from config.settings.AppSettings import AppSettings


class TestSettings(AppSettings):
    debug: bool = True

    class Config:
        env_file = ["./envs/test.env", "./envs/base.env"]
        env_file_encoding = "utf-8"
        extra = "ignore"
