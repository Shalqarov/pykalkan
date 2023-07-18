from typing import Any

from .C.kalkan import KCCLient as _KCClient, new_kc_client
from .kalkan_interface import KalkanInterface


class Client(KalkanInterface):
    def __init__(self, kc: _KCClient):
        self._kc = kc

    def init(self) -> int:
        return self._kc.kc_init()

    def load_key_store(self, cert_path: str, cert_password: str) -> int:
        return self._kc.load_key_store(cert_path, cert_password)

    def finalize(self):
        self._kc.finalize()

    def x509_export_certificate_from_store(self):
        return self._kc.x509_export_certificate_from_store()

    def x509_load_certificate_from_buffer(self, in_cert: str) -> int:
        return self._kc.x509_load_certificate_from_buffer(in_cert)

    def x509_certificate_get_info(self, in_cert: str) -> tuple[int, Any]:
        return self._kc.x509_certificate_get_info(in_cert)

    def sign_data(self, data):
        return self._kc.sign_data(data)

    def verify_data(self, signature: str, data: str) -> tuple[int, dict[str, Any]]:
        return self._kc.verify_data(signature, data)

    def x509_validate_certificate(self, in_cert: str):
        return self._kc.x509_validate_certificate(in_cert)


def new_client(lib: str) -> Client:
    try:
        kc = new_kc_client(lib)
        return Client(kc)
    except OSError as e:
        raise OSError(f"Error in new_client() /kalkan_crypt/adapter.py:21: \n{e}")
