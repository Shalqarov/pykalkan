from abc import ABC, abstractmethod
from typing import Any


class KalkanInterface(ABC):
    """ Методы которые нужно реализовать в клиенте """

    @abstractmethod
    def init(self) -> int:
        ...

    @abstractmethod
    def load_key_store(self, cert_path: str, cert_password: str) -> int:
        ...

    @abstractmethod
    def finalize(self):
        ...

    @abstractmethod
    def x509_export_certificate_from_store(self):
        ...

    @abstractmethod
    def x509_load_certificate_from_buffer(self, in_cert: str) -> int:
        ...

    @abstractmethod
    def x509_certificate_get_info(self, in_cert: str) -> tuple[int, Any]:
        ...

    @abstractmethod
    def sign_data(self, data: str):
        ...

    @abstractmethod
    def verify_data(self, signature: str, data: str) -> tuple[int, dict[str, Any]]:
        ...
