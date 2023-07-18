from typing import Any

from .dl_open import get_libhandle as _get_libhandle


class KCCLient:
    """ Логика вызова методов из библиотеки """

    def __init__(self, lib: str):
        self.handler = _get_libhandle(lib)

    def kc_init(self) -> int:
        return self.handler.kc_init()

    def load_key_store(self, path: str, password: str) -> int:
        return self.handler.kc_load_key_store(path, password)

    def finalize(self):
        self.handler.kc_finalize()

    def x509_export_certificate_from_store(self):
        return self.handler.x509_export_certificate_from_store()

    def x509_load_certificate_from_buffer(self, in_cert: str) -> int:
        return self.handler.x509_load_certificate_from_buffer(in_cert.encode())

    def x509_certificate_get_info(self, in_cert: str) -> tuple[int, Any]:
        return self.handler.x509_certificate_get_info(in_cert.encode())

    def sign_data(self, data: str):
        return self.handler.sign_data(data.encode())

    def verify_data(self, signature: str, data: str) -> tuple[int, dict[str, Any]]:
        return self.handler.verify_data(signature.encode(), in_data=data.encode())

    def x509_validate_certificate(self, in_cert: str):
        return self.handler.x509_validate_certificate(in_cert.encode())
