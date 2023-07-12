from typing import Final


def wrap_error(code: int) -> str:
    return ErrorCode(code).__str__()


class ErrorCode:
    def __init__(self, code: int):
        self.code = code

    def __str__(self) -> str:
        if self.code in error_labels:
            return error_labels[self.code]
        return f"Неизвестный код ошибки: {self.code}"


KC_OK: Final[ErrorCode] = ErrorCode(0)  # Нет ошибки
KC_ERROR_READ_PKCS12: Final[ErrorCode] = ErrorCode(149946370)  # Невозможно прочитать файл формата pkcs#12
KC_ERROR_OPEN_PKCS12: Final[ErrorCode] = ErrorCode(149946371)  # Невозможно открыть файл формата pkcs#12
KC_INVALID_PROP_ID: Final[ErrorCode] = ErrorCode(149946372)  # Недопустимый идентификатор расширения сертификата
KC_BUFFER_TOO_SMALL: Final[ErrorCode] = ErrorCode(149946373)  # Размер буфера слишком мал
KC_CODE_CERT_PARSE_ERROR: Final[ErrorCode] = ErrorCode(149946374)  # Невозможно разобрать (распарсить) сертификат
KC_INVALID_FLAG: Final[ErrorCode] = ErrorCode(149946375)  # Недопустимый флаг
KC_OPEN_FILE_ERR: Final[ErrorCode] = ErrorCode(149946376)  # Невозможно открыть файл
KC_INVALID_PASSWORD: Final[ErrorCode] = ErrorCode(149946377)  # Неправильный пароль
KC_MEMORY_ERROR: Final[ErrorCode] = ErrorCode(149946381)  # Невозможно выделить память
KC_CHECK_CHAIN_ERROR: Final[ErrorCode] = ErrorCode(
    149946382)  # Не найден сертификат УЦ или сертификат пользователя при проверки цепочки
KC_VALID_TYPE_ERROR: Final[ErrorCode] = ErrorCode(149946384)  # Недопустимый тип валидации сертификата
KC_BAD_CRL_FORMAT: Final[ErrorCode] = ErrorCode(149946385)  # Некорректный формат CRL

error_labels = {
    KC_OK.code: "Нет ошибки",
    KC_ERROR_READ_PKCS12.code: "Невозможно прочитать файл формата pkcs#12",
    KC_INVALID_PASSWORD.code: "Неправильный пароль",
}
