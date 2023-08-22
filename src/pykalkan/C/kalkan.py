from pykalkan.enums import ValidateType
from .dl_open import LibHandle


class KCCLient:
    """Логика вызова методов из библиотеки"""

    def __init__(self, lib: str):
        self.handler = LibHandle(lib)

    def kc_init(self):
        self.handler.kc_init()

    def load_key_store(self, path: str, password: str):
        self.handler.kc_load_key_store(path, password)

    def finalize(self):
        self.handler.kc_finalize()

    def x509_export_certificate_from_store(self) -> bytes:
        return self.handler.x509_export_certificate_from_store()

    def x509_load_certificate_from_buffer(self, in_cert: str):
        self.handler.x509_load_certificate_from_buffer(in_cert.encode())

    def x509_certificate_get_info(self, in_cert: str) -> bytes:
        return self.handler.x509_certificate_get_info(in_cert.encode())

    def sign_data(self, data: str) -> bytes:
        return self.handler.sign_data(data.encode())

    def verify_data(self, signature: str, data: str) -> dict[str, bytes]:
        return self.handler.verify_data(signature.encode(), in_data=data.encode())

    def x509_validate_certificate_ocsp(self, in_cert: str) -> dict[str, bytes]:
        return self.handler.x509_validate_certificate(
            in_cert.encode(),
            ValidateType.KC_USE_OCSP,
        )

    def x509_validate_certificate_crl(self, in_cert: str, crl_path: str) -> dict[str, bytes]:
        return self.handler.x509_validate_certificate(
            in_cert.encode(),
            ValidateType.KC_USE_CRL,
            crl_path.encode(),
        )

    def get_time(self, in_data: str) -> int:
        return self.handler.get_time_from_sign(in_data.encode())

    def set_tsa_url(self):
        self.handler.set_tsa_url()
