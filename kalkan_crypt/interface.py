from abc import ABC, abstractmethod


class KalkanInterface(ABC):
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
    def x509_export_certificate_from_store(self) -> tuple[int, bytes]:
        ...

    @abstractmethod
    def x509_load_certificate_from_buffer(self, in_cert: str) -> int:
        ...

    @abstractmethod
    def x509_certificate_get_info(self, in_cert: str) -> tuple[int, bytes]:
        ...

    @abstractmethod
    def sign_data(self, data) -> tuple[int, bytes]:
        ...

    @abstractmethod
    def verify_data(self, signature: str, data: str) -> tuple[int, dict[str, bytes]]:
        ...

    @abstractmethod
    def x509_validate_certificate(self, in_cert: str) -> tuple[int, dict[str, bytes]]:
        ...
