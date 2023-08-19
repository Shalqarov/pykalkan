from abc import ABC, abstractmethod


class KalkanInterface(ABC):
    @abstractmethod
    def init(self):
        pass

    @abstractmethod
    def load_key_store(self, cert_path: str, cert_password: str):
        pass

    @abstractmethod
    def finalize(self):
        pass

    @abstractmethod
    def x509_export_certificate_from_store(self) -> bytes:
        pass

    @abstractmethod
    def x509_load_certificate_from_buffer(self, in_cert: str):
        pass

    @abstractmethod
    def x509_certificate_get_info(self, in_cert: str) -> bytes:
        pass

    @abstractmethod
    def sign_data(self, data) -> bytes:
        pass

    @abstractmethod
    def verify_data(self, signature: str, data: str) -> dict[str, bytes]:
        pass

    @abstractmethod
    def x509_validate_certificate(self, in_cert: str) -> dict[str, bytes]:
        pass

    @abstractmethod
    def get_time_from_sign(self, sign: str) -> int:
        pass

    @abstractmethod
    def set_tsa_url(self):
        pass
