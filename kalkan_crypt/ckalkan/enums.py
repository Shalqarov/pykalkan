from enum import IntEnum


class StorageType(IntEnum):
    KCST_PKCS12 = 0x1
    KCST_KZIDCARD = 0x2
    KCST_KAZTOKEN = 0x4
    KCST_ETOKEN72K = 0x8
    KCST_JACARTA = 0x10
    KCST_X509CERT = 0x20
    KCST_AKEY = 0x40


class SignatureFlag(IntEnum):
    KC_SIGN_DRAFT = 0x1  # Сырая подпись (draft sign)
    KC_SIGN_CMS = 0x2  # Подпись в формате CMS
    KC_IN_PEM = 0x4  # Входные данные в формате PEM
    KC_IN_DER = 0x8  # Входные данные в кодировке DER
    KC_IN_BASE64 = 0x10  # Входные данные в кодировке BASE64
    KC_IN2_BASE64 = 0x20  # Дополнительные входные данные в кодировке BASE64
    KC_DETACHED_DATA = 0x40  # Отсоединенная подпись
    KC_WITH_CERT = 0x80  # Вложить сертификат в подпись
    KC_WITH_TIMESTAMP = 0x100  # Добавить в подпись метку времени
    KC_OUT_PEM = 0x200  # Выходные данные в формате PEM
    KC_OUT_DER = 0x400  # Выходные данные в кодировке DER
    KC_OUT_BASE64 = 0x800  # Выходные данные в кодировке BASE64
    KC_PROXY_OFF = 0x00001000  # Отключить использование прокси-сервера и стереть настройки.
    KC_PROXY_ON = 0x00002000  # Включить и установить настройки прокси-сервера (адрес и порт)
    KC_PROXY_AUTH = 0x00004000  # Прокси-сервер требует авторизацию (логин/пароль)
    KC_IN_FILE = 0x00008000  # Использовать, если параметр inData/outData содержит абсолютный путь к файлу.
    KC_NOCHECKCERTTIME = 0x00010000  # Не проверять срок действия сертификата при построении цепочки до корневого (для проверки старых подписей с просроченным сертификатом)
    KC_HASH_SHA256 = 0x00020000  # Алгоритм хеширования sha256
    KC_HASH_GOST95 = 0x00040000  # Алгоритм хеширования Gost34311_95
    KC_GET_OCSP_RESPONSE = 0x00080000  # Получить ответ от OCSP-сервиса
