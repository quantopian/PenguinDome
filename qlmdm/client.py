from qlmdm import (
    load_settings,
    get_setting as main_get_setting,
    set_setting as main_set_setting,
    get_logger as main_get_logger,
    save_settings as main_save_settings,
    get_selectors as main_get_selectors,
    encrypt_document as main_encrypt_document,
)


def get_setting(setting, default=None, check_defaults=True):
    return main_get_setting(load_settings('client'), setting, default,
                            check_defaults)


def set_setting(setting, value):
    return main_set_setting(load_settings('client'), setting, value)


def save_settings():
    main_save_settings('client')


def get_logger(name):
    return main_get_logger(get_setting, name)


def get_selectors():
    return main_get_selectors(get_setting)


def encrypt_document(doc, log=None):
    return main_encrypt_document(get_setting, doc, log=log)
