from .C.kalkan import KCCLient as _KCCLient
from .interface import KalkanInterface


class Adapter(KalkanInterface):
    def __init__(self, lib: str):
        self._kc = _KCCLient(lib)

    def init(self):
        self._kc.kc_init()

    def load_key_store(self, cert_path: str, cert_password: str):
        self._kc.load_key_store(cert_path, cert_password)

    def finalize(self):
        self._kc.finalize()

    def x509_export_certificate_from_store(self) -> bytes:
        return self._kc.x509_export_certificate_from_store()

    def x509_load_certificate_from_buffer(self, in_cert: str):
        self._kc.x509_load_certificate_from_buffer(in_cert)

    def x509_certificate_get_info(self, in_cert: str) -> bytes:
        return self._kc.x509_certificate_get_info(in_cert)

    def sign_data(self, data) -> bytes:
        return self._kc.sign_data(data)

    def verify_data(self, signature: str, data: str) -> dict[str, bytes]:
        return self._kc.verify_data(signature, data)

    def x509_validate_certificate(self, in_cert: str) -> dict[str, bytes]:
        return self._kc.x509_validate_certificate_ocsp(in_cert)

    def get_time_from_sign(self, sign: str) -> int:
        return self._kc.get_time(sign)

    def set_tsa_url(self):
        self._kc.set_tsa_url()
