from pykalkan.error_codes import ErrorCode, ErrorMessage


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
        try:
            code = ErrorCode(self.status)
            error_message = ErrorMessage[code.name].value
        except ValueError:
            error_message = f"Неизвестная ошибка: {self.status}"
        return f"Function: {self.func}; Code: {self.status}; Error: {error_message}; Info: {self.info}"
