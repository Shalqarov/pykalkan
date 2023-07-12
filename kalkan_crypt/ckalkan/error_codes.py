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


ERROR_CODE_OK: Final[ErrorCode] = ErrorCode(0)  # Нет ошибки
ERROR_CODE_ERROR_READ_PKCS12: Final[ErrorCode] = ErrorCode(149946370)  # Невозможно прочитать файл формата pkcs#12
ERROR_CODE_INVALID_PASSWORD: Final[ErrorCode] = ErrorCode(149946377)  # Неправильный пароль

error_labels = {
    ERROR_CODE_OK.code: "Нет ошибки",
    ERROR_CODE_ERROR_READ_PKCS12.code: "Невозможно прочитать файл формата pkcs#12",
    ERROR_CODE_INVALID_PASSWORD.code: "Неправильный пароль",
}
