from qlmdm import (
    load_settings,
    get_setting as main_get_setting,
    get_logger as main_get_logger,
)


def get_setting(setting, default=None, check_defaults=True):
    return main_get_setting(load_settings('client'), setting, default,
                            check_defaults)


def get_logger(name):
    return main_get_logger(get_setting, name)
