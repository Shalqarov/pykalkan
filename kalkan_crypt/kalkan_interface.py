from abc import ABC, abstractmethod


class KalkanInterface(ABC):
    """ Методы которые нужно реализовать """

    @abstractmethod
    def init(self) -> int:
        ...

    @abstractmethod
    def load_key_store(self, cert_path: str, cert_password: str) -> int:
        ...

    @abstractmethod
    def finalize(self):
        ...
