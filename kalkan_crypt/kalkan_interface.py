from abc import ABC, abstractmethod


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
    def verify_data(self, signature):
        ...
