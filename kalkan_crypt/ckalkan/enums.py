from enum import IntEnum


class CertProp(IntEnum):
    KC_ISSUER_COUNTRYNAME = 0x00000801  # Страна издателя
    KC_ISSUER_SOPN = 0x00000802  # Название штата или провинции издателя
    KC_ISSUER_LOCALITYNAME = 0x00000803  # Населённый пункт издателя
    KC_ISSUER_ORG_NAME = 0x00000804  # Наименование организации издателя
    KC_ISSUER_ORGUNIT_NAME = 0x00000805  # Название организационного подразделения издателя
    KC_ISSUER_COMMONNAME = 0x00000806  # Имя Фамилия издателя
    KC_SUBJECT_COUNTRYNAME = 0x00000807  # Страна субъекта
    KC_SUBJECT_SOPN = 0x00000808  # Название штата или провинции субъекта
    KC_SUBJECT_LOCALITYNAME = 0x00000809  # Населенный пункт субъекта
    KC_SUBJECT_COMMONNAME = 0x0000080a  # Общее имя субъекта
    KC_SUBJECT_GIVENNAME = 0x0000080b  # Имя субъекта
    KC_SUBJECT_SURNAME = 0x0000080c  # Фамилия субъекта
    KC_SUBJECT_SERIALNUMBER = 0x0000080d  # Серийный номер субъекта
    KC_SUBJECT_EMAIL = 0x0000080e  # e-mail субъекта
    KC_SUBJECT_ORG_NAME = 0x0000080f  # Наименование организации субъекта
    KC_SUBJECT_ORGUNIT_NAME = 0x00000810  # Название организационного подразделения субъекта
    KC_SUBJECT_BC = 0x00000811  # Бизнес категория субъекта
    KC_SUBJECT_DC = 0x00000812  # Доменный компонент субъекта
    KC_NOTBEFORE = 0x00000813  # Дата действителен с
    KC_NOTAFTER = 0x00000814  # Дата действителен по
    KC_KEY_USAGE = 0x00000815  # Использование ключа
    KC_EXT_KEY_USAGE = 0x00000816  # Расширенное использование ключа
    KC_AUTH_KEY_ID = 0x00000817  # Идентификатор ключа центра сертификации
    KC_SUBJ_KEY_ID = 0x00000818  # Идентификатор ключа субъекта
    KC_CERT_SN = 0x00000819  # Серийный номер сертификата
    KC_ISSUER_DN = 0x0000081a  # Отличительное имя издателя
    KC_SUBJECT_DN = 0x0000081b  # Отличительное имя субъекта
    KC_SIGNATURE_ALG = 0x0000081c  # Алгоритм подписи
    KC_PUBKEY = 0x0000081d  # Получение открытого ключа
    KC_POLICIES_ID = 0x0000081e  # Получение идентификатора политики сертификата
    KC_OCSP = 0x0000081f  # Получение URL-адреса OCSP
    KC_GET_CRL = 0x00000820  # Получение URL-адреса CRL
    KC_GET_DELTA_CRL = 0x00000821  # Получение URL-адреса delta CRL


class StorageType(IntEnum):
    KCST_PKCS12 = 0x00000001  # Файловая система (небезопасный способ хранения ключей)
    KCST_KZIDCARD = 0x00000002  # Удостоверение личности гражданина РК
    KCST_KAZTOKEN = 0x00000004  # Казтокен
    KCST_ETOKEN72K = 0x00000008  # eToken 72k
    KCST_JACARTA = 0x00000010  # JaCarta
    KCST_X509CERT = 0x00000020  # Сертификат X509
    KCST_AKEY = 0x00000040  # aKey


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
