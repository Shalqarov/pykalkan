from enum import Enum


class KalkanException(Exception):
    def __init__(self, status, func_name, info=None, *args):
        super().__init__(args)
        self.status = status
        self.info = info
        self.func = func_name

    def __str__(self):
        try:
            code = ErrorCode(self.status)
            error_message = ErrorMessage[code.name].value
        except ValueError:
            error_message = f"Неизвестная ошибка: {self.status}"
        return f"Function: {self.func}; Code: {self.status}; Error: {error_message}"


class ValidateException(KalkanException):
    def __str__(self):
        error_message = (
            ErrorCode(self.status).value[1]
            if ErrorCode(self.status)
            else f"Неизвестная ошибка: {self.status}"
        )
        return f"Function: {self.func}; Code: {self.status}; Error: {error_message}; Info: {self.info}"


class ErrorCode(Enum):
    KCR_OK = 0x00000000
    KCR_ERROR_READ_PKCS12 = 0x08F00002
    KCR_ERROR_OPEN_PKCS12 = 0x08F00003
    KCR_INVALID_PROPID = 0x08F00004
    KCR_BUFFER_TOO_SMALL = 0x08F00005
    KCR_CERT_PARSE_ERROR = 0x08F00006
    KCR_INVALID_FLAG = 0x08F00007
    KCR_OPENFILEERR = 0x08F00008
    KCR_INVALIDPASSWORD = 0x08F00009
    KCR_MEMORY_ERROR = 0x08F0000D
    KCR_CHECKCHAINERROR = 0x08F0000E
    KCR_VALIDTYPEERROR = 0x08F00010
    KCR_BADCRLFORMAT = 0x08F00011
    KCR_LOADCRLERROR = 0x08F00012
    KCR_LOADCRLSERROR = 0x08F00013
    KCR_UNKNOWN_ALG = 0x08F00015
    KCR_KEYNOTFOUND = 0x08F00016
    KCR_SIGN_INIT_ERROR = 0x08F00017
    KCR_SIGN_ERROR = 0x08F00018
    KCR_ENCODE_ERROR = 0x08F00019
    KCR_INVALID_FLAGS = 0x08F0001A
    KCR_CERTNOTFOUND = 0x08F0001B
    KCR_VERIFYSIGNERROR = 0x08F0001C
    KCR_BASE64_DECODE_ERROR = 0x08F0001D
    KCR_UNKNOWN_CMS_FORMAT = 0x08F0001E
    KCR_CA_CERT_NOT_FOUND = 0x08F00020
    KCR_XMLSECINIT_ERROR = 0x08F00021
    KCR_LOADTRUSTEDCERTSERR = 0x08F00022
    KCR_SIGN_INVALID = 0x08F00023
    KCR_NOSIGNFOUND = 0x08F00024
    KCR_DECODE_ERROR = 0x08F00025
    KCR_XMLPARSEERROR = 0x08F00026
    KCR_XMLADDIDERROR = 0x08F00027
    KCR_XMLINTERNALERROR = 0x08F00028
    KCR_XMLSETSIGNERROR = 0x08F00029
    KCR_OPENSSLERROR = 0x08F0002A
    KCR_NOTOKENFOUND = 0x08F0002C
    KCR_OCSP_ADDCERTERR = 0x08F0002D
    KCR_OCSP_PARSEURLERR = 0x08F0002E
    KCR_OCSP_ADDHOSTERR = 0x08F0002F
    KCR_OCSP_REQERR = 0x08F00030
    KCR_OCSP_CONNECTIONERR = 0x08F00031
    KCR_VERIFY_NODATA = 0x08F00032
    KCR_IDATTR_NOTFOUND = 0x08F00033
    KCR_IDRANGE = 0x08F00034
    KCR_READERNOTFOUND = 0x08F00037
    KCR_GETCERTPROPERR = 0x08F00038
    KCR_SIGNFORMMAT = 0x08F00039
    KCR_INDATAFORMAT = 0x08F0003A
    KCR_OUTDATAFORMAT = 0x08F0003B
    KCR_VERIFY_INIT_ERROR = 0x08F0003C
    KCR_VERIFY_ERROR = 0x08F0003D
    KCR_HASH_ERROR = 0x08F0003E
    KCR_SIGNHASH_ERROR = 0x08F0003F
    KCR_CACERTNOTFOUND = 0x08F00040
    KCR_CERTTIMEINVALID = 0x08F00042
    KCR_CONVERTERROR = 0x08F00043
    KCR_TSACREATEQUERY = 0x08F00044
    KCR_CREATEOBJ = 0x08F00045
    KCR_CREATENONCE = 0x08F00046
    KCR_HTTPERROR = 0x08F00047
    KCR_CADESBES_FAILED = 0x08F00048
    KCR_CADEST_FAILED = 0x08F00049
    KCR_NOTSATOKEN = 0x08F0004A
    KCR_INVALID_DIGEST_LEN = 0x08F0004B
    KCR_GENRANDERROR = 0x08F0004C
    KCR_SOAPNSERROR = 0x08F0004D
    KCR_GETPUBKEY = 0x08F0004E
    KCR_GETCERTINFO = 0x08F0004F
    KCR_FILEREADERROR = 0x08F00050
    KCR_CHECKERROR = 0x08F00051
    KCR_ZIPEXTRACTERR = 0x08F00052
    KCR_NOMANIFESTFILE = 0x08F00053
    KCR_VERIFY_TS_HASH = 0x08F00054
    KCR_XADEST_FAILED = 0x08F00055
    KCR_OCSP_RESP_STAT_MALFORMEDREQUEST = 0x08F00056
    KCR_OCSP_RESP_STAT_INTERNALERROR = 0x08F00057
    KCR_OCSP_RESP_STAT_TRYLATER = 0x08F00058
    KCR_OCSP_RESP_STAT_SIGREQUIRED = 0x08F00059
    KCR_OCSP_RESP_STAT_UNAUTHORIZED = 0x08F0005A
    KCR_VERIFY_ISSUERSERIALV2 = 0x08F0005B
    KCR_OCSP_CHECKCERTFROMRESP = 0x08F0005C
    KCR_CRLEXPIRED = 0x08F0005D
    KCR_LIBRARYNOTINITIALIZED = 0x08F00101
    KCR_ENGINELOADERR = 0x08F00200
    KCR_PARAM_ERROR = 0x08F00300
    KCR_CERT_STATUS_OK = 0x08F00400
    KCR_CERT_STATUS_REVOKED = 0x08F00401
    KCR_CERT_STATUS_UNKNOWN = 0x08F00402


class ErrorMessage(Enum):
    KCR_OK = "Нет ошибки"
    KCR_ERROR_READ_PKCS12 = "Невозможно прочитать файл формата pkcs#12"
    KCR_ERROR_OPEN_PKCS12 = "Невозможно открыть файл формата pkcs12"
    KCR_INVALID_PROPID = "Недопустимый идентификатор расширения сертификата"
    KCR_BUFFER_TOO_SMALL = "Размер буфера слишком мал"
    KCR_CERT_PARSE_ERROR = "Невозможно разобрать (распарсить) сертификат"
    KCR_INVALID_FLAG = "Недопустимый флаг"
    KCR_OPENFILEERR = "Невозможно открыть файл"
    KCR_INVALIDPASSWORD = "Неправильный пароль"
    KCR_MEMORY_ERROR = "Невозможно выделить память"
    KCR_CHECKCHAINERROR = (
        "Не найден сертификат УЦ или сертификат пользователя при проверки цепочки"
    )
    KCR_VALIDTYPEERROR = "Недопустимый тип валидации сертификата"
    KCR_BADCRLFORMAT = "Некорректный формат CRL"
    KCR_LOADCRLERROR = "Невозможно загрузить CRL"
    KCR_LOADCRLSERROR = "Невозможно загрузить CRL-ы"
    KCR_UNKNOWN_ALG = "Неизвестный алгоритм подписи"
    KCR_KEYNOTFOUND = "Не найден приватный ключ пользователя"
    KCR_SIGN_INIT_ERROR = "Невозможно инициализировать менеджера подписи"
    KCR_SIGN_ERROR = "Не удалось сгенерировать цифровую подпись"
    KCR_ENCODE_ERROR = "Ошибка шифрования"
    KCR_INVALID_FLAGS = "Недопустимые флаги"
    KCR_CERTNOTFOUND = "Не найден сертификат пользователя"
    KCR_VERIFYSIGNERROR = "Ошибка верификации подписи xml"
    KCR_BASE64_DECODE_ERROR = "Ошибка дешифровки из Base 64"
    KCR_UNKNOWN_CMS_FORMAT = "Неизвестный формат CMS"
    KCR_CA_CERT_NOT_FOUND = "Не найден сертификат УЦ"
    KCR_XMLSECINIT_ERROR = "Ошибка инициализации xmlsec"
    KCR_LOADTRUSTEDCERTSERR = "Ошибка загрузки доверенных сертификатов"
    KCR_SIGN_INVALID = "Недопустимая подпись xml"
    KCR_NOSIGNFOUND = "Не найдена подпись во входных данных"
    KCR_DECODE_ERROR = "Ошибка дешифрования"
    KCR_XMLPARSEERROR = "Невозможно разобрать (распарсить) xml"
    KCR_XMLADDIDERROR = "Не удалось добавить атрибут ID"
    KCR_XMLINTERNALERROR = "Ошибка при работе с xml"
    KCR_XMLSETSIGNERROR = "Не удалось подписать xml"
    KCR_OPENSSLERROR = "Ошибка openssl"
    KCR_NOTOKENFOUND = "Не найден токен"
    KCR_OCSP_ADDCERTERR = "Не удалось добавить сертификат в ocsp"
    KCR_OCSP_PARSEURLERR = "Не удалось разобрать url"
    KCR_OCSP_ADDHOSTERR = "Не удалось добавить хост"
    KCR_OCSP_REQERR = "Не удалось добавить текущее время в запрос"
    KCR_OCSP_CONNECTIONERR = "Ошибка подключения к OCSP респондеру"
    KCR_VERIFY_NODATA = "Нет входных данных для верификации"
    KCR_IDATTR_NOTFOUND = "Не найден атрибут ID"
    KCR_IDRANGE = "Некорректный идентификатор"
    KCR_READERNOTFOUND = "Не найден ридер"
    KCR_GETCERTPROPERR = "Не удалось получить значение атрибута"
    KCR_SIGNFORMMAT = "Неизвестный формат подписи"
    KCR_INDATAFORMAT = "Неизвестный формат входных данных"
    KCR_OUTDATAFORMAT = "Неизвестный формат выходных данных"
    KCR_VERIFY_INIT_ERROR = "Невозможно инициализировать менеджера верификации подписи"
    KCR_VERIFY_ERROR = "Не удалось верифицировать цифровую подпись"
    KCR_HASH_ERROR = "Не удалось хэшировать данные"
    KCR_SIGNHASH_ERROR = "Не удалось подписать хэшированные данные"
    KCR_CACERTNOTFOUND = "Не найден сертификат УЦ в хранилище сертификатов"
    KCR_CERTTIMEINVALID = "Срок действия сертификата истек либо еще не наступил"
    KCR_CONVERTERROR = "Ошибка записи сертификата в структуру X509"
    KCR_TSACREATEQUERY = "Ошибка генерации запроса timestamp"
    KCR_CREATEOBJ = "Ошибка записи OID в ASN1 структуру"
    KCR_CREATENONCE = "Ошибка генерации уникального числа"
    KCR_HTTPERROR = "Ошибка протокола http"
    KCR_CADESBES_FAILED = "Ошибка проверки расширения CADESBES в CMS"
    KCR_CADEST_FAILED = "Ошибка проверки подписи токена TSA"
    KCR_NOTSATOKEN = "В подписи не присутствует метка TSA"
    KCR_INVALID_DIGEST_LEN = "Неправильная длина хэша"
    KCR_GENRANDERROR = "Ошибка генерации случайного числа"
    KCR_SOAPNSERROR = "Не найдены заголовки SOAP-сообщений"
    KCR_GETPUBKEY = "Ошибка экспорта публичного ключа"
    KCR_GETCERTINFO = "Ошибка получения информации о сертификате"
    KCR_FILEREADERROR = "Ошибка чтения файла"
    KCR_CHECKERROR = "Хэш не совпадает"
    KCR_ZIPEXTRACTERR = "Невозможно открыть архив"
    KCR_NOMANIFESTFILE = "Не найден MANIFEST"
    KCR_VERIFY_TS_HASH = "не удалось проверить Хэш подписи TS"
    KCR_XADEST_FAILED = "XAdES-T: Ошибка проверки подписи"
    KCR_OCSP_RESP_STAT_MALFORMEDREQUEST = "Неправильный запрос"
    KCR_OCSP_RESP_STAT_INTERNALERROR = "Внутренняя ошибка"
    KCR_OCSP_RESP_STAT_TRYLATER = "Попробуйте позже"
    KCR_OCSP_RESP_STAT_SIGREQUIRED = "Должны подписать запрос"
    KCR_OCSP_RESP_STAT_UNAUTHORIZED = "Запрос не авторизован"
    KCR_VERIFY_ISSUERSERIALV2 = "не удалось проверить IssuerSerialV2 в XAdES"
    KCR_OCSP_CHECKCERTFROMRESP = "Ошибка проверки сертификата OCSP-респондера"
    KCR_CRLEXPIRED = "CRL-файл просрочен"
    KCR_LIBRARYNOTINITIALIZED = "Библиотека не инициализирована"
    KCR_ENGINELOADERR = "Ошибка подключения (загрузки) модуля (engine)"
    KCR_PARAM_ERROR = "Некорректные входные данные"
    KCR_CERT_STATUS_OK = (
        "Статус сертификата – валидный. (не является ошибкой, делается запись в лог)"
    )
    KCR_CERT_STATUS_REVOKED = "Статус сертификата – отозван."
    KCR_CERT_STATUS_UNKNOWN = "Статус сертификата – неизвестен. Например, не удалось установить издателя сертификата."
