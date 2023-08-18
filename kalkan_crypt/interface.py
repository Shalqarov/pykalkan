from abc import ABC, abstractmethod


class KalkanInterface(ABC):
    @abstractmethod
    def init(self):
        ...

    @abstractmethod
    def load_key_store(self, cert_path: str, cert_password: str):
        ...

    @abstractmethod
    def finalize(self):
        ...

    @abstractmethod
    def x509_export_certificate_from_store(self) -> bytes:
        ...

    @abstractmethod
    def x509_load_certificate_from_buffer(self, in_cert: str):
        ...

    @abstractmethod
    def x509_certificate_get_info(self, in_cert: str) -> bytes:
        ...

    @abstractmethod
    def sign_data(self, data) -> bytes:
        ...

    @abstractmethod
    def verify_data(self, signature: str, data: str) -> dict[str, bytes]:
        ...

    @abstractmethod
    def x509_validate_certificate(self, in_cert: str) -> dict[str, bytes]:
        ...

    @abstractmethod
    def get_time_from_sign(self, sign: str) -> int:
        ...
