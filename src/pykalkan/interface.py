import typing as t
from abc import ABC, abstractmethod

from pykalkan.enums import CertCode, CertProp, SignatureFlag


class KalkanInterface(ABC):
    @abstractmethod
    def init(self):
        pass

    @abstractmethod
    def load_key_store(self, cert_path: str, cert_password: str, store_type: int, alias: str):
        pass

    @abstractmethod
    def finalize(self):
        pass

    @abstractmethod
    def x509_export_certificate_from_store(self) -> bytes:
        pass

    @abstractmethod
    def x509_load_certificate_from_buffer(self, in_cert: str, cert_code: CertCode):
        pass

    @abstractmethod
    def x509_certificate_get_info(self, in_cert: str, cert_prop: CertProp) -> bytes:
        pass

    @abstractmethod
    def sign_data(self, data: str, flags: t.Iterable[SignatureFlag]) -> bytes:
        pass

    @abstractmethod
    def verify_data(self, signature: str, data: str, flags: t.Iterable[SignatureFlag]) -> dict[str, bytes]:
        pass

    @abstractmethod
    def x509_validate_certificate_ocsp(self, in_cert: str) -> dict[str, bytes]:
        pass

    @abstractmethod
    def x509_validate_certificate_crl(self, in_cert: str, crl_path: str) -> dict[str, bytes]:
        pass

    @abstractmethod
    def get_time_from_sign(self, sign: str, flags: t.Iterable[SignatureFlag]) -> int:
        pass

    @abstractmethod
    def set_tsa_url(self, url: str):
        pass
