import multiprocessing
import typing as t

from pykalkan.enums import CertCode, CertProp, SignatureFlag, ValidateType
from .C.lib_handle import LibHandle
from .interface import KalkanInterface


class Adapter(KalkanInterface):
    """
    Adapter
    Класс, представляющий адаптер для криптографической библиотеки Kalkan.
    """
    _instance = None
    _lib = None

    def __new__(cls, lib: str):
        if cls._instance is None:
            _lib = lib
            cls._instance = super(Adapter, cls).__new__(cls)
            cls._lock = multiprocessing.Lock()
            cls._instance._kc = LibHandle(_lib)
        return cls._instance

    def __enter__(self):
        if self._instance is None:
            self._instance = super(Adapter, self.__class__).__new__(self.__class__)
            self._instance._kc = LibHandle(self._lib)
        self.init()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._kc.kc_finalize()
        self._instance = None

    def init(self):
        """Инициализация библиотеки.."""
        with self._lock:
            self._kc.kc_init()

    def load_key_store(
            self,
            cert_path: str,
            cert_password: str,
            store_type: t.Optional[int] = 1,
            alias: t.Optional[str] = ""
    ):
        """
        Загружает хранилище ключей из заданного пути к файлу сертификата и пароля.
        :param cert_path: str - Путь к файлу сертификата.
        :param cert_password: str - Пароль для сертификата.
        :param store_type: int - тип хранилища(по умолчанию 1).
        :param alias: str - Алиас хранилища.
        """
        with self._lock:
            self._kc.kc_load_key_store(cert_path, cert_password, store_type, alias)

    def finalize(self):
        """Освобождает ресурсы криптопровайдера KalkanCryptCOM и завершает работу библиотеки."""
        with self._lock:
            self._kc.kc_finalize()
            self._instance = None

    def x509_export_certificate_from_store(self) -> bytes:
        """
        Экспорт сертификата из хранилища.
        :return: bytes - Экспортированный сертификат.
        """
        with self._lock:
            return self._kc.x509_export_certificate_from_store()

    def x509_load_certificate_from_buffer(self, in_cert: str, cert_code: t.Optional[CertCode] = CertCode.KC_CERT_B64):
        """
        Загрузка сертификата из памяти.
        :param in_cert: str - сертификат.
        :param cert_code: str - флаги.
        """
        with self._lock:
            self._kc.x509_load_certificate_from_buffer(in_cert.encode(), cert_code)

    def x509_certificate_get_info(self, in_cert: str, cert_prop: CertProp) -> bytes:
        """
        Обеспечивает получение значений полей/расширений из сертификата.
        :param in_cert: str - Сертификат, для которого необходимо получить информацию.
        :param cert_prop: Поле сертификата, которое нужно вытащить
        :return: bytes - Информация о сертификате.
        """
        with self._lock:
            return self._kc.x509_certificate_get_info(in_cert.encode(), cert_prop)

    def sign_data(
            self,
            data: str,
            flags: t.Iterable[SignatureFlag] = (
                    SignatureFlag.KC_SIGN_CMS,
                    SignatureFlag.KC_IN_BASE64,
                    SignatureFlag.KC_OUT_BASE64,
                    SignatureFlag.KC_WITH_CERT,
                    SignatureFlag.KC_WITH_TIMESTAMP,
            )) -> bytes:
        """
        Подписывает данные.
        :param data - Данные для подписи.
        :param flags - флаги.
        :return: bytes - Подписанные данные.
        """
        with self._lock:
            return self._kc.sign_data(data.encode(), flags)

    def verify_data(
            self,
            signature: str,
            data: str,
            flags: t.Iterable[SignatureFlag] = (
                    SignatureFlag.KC_SIGN_CMS,
                    SignatureFlag.KC_IN_BASE64,
                    SignatureFlag.KC_IN2_BASE64,
                    SignatureFlag.KC_DETACHED_DATA,
                    SignatureFlag.KC_WITH_CERT,
                    SignatureFlag.KC_OUT_BASE64,
            ),
    ) -> dict[str, bytes]:
        """
        Обеспечивает проверку подписи.
        :param signature: str - Проверяемая подпись.
        :param data: str - Проверяемые данные.
        :param flags: флаги.
        :return: dict[str, bytes] - Словарь, содержащий результат проверки.
        """
        with self._lock:
            return self._kc.verify_data(signature.encode(), data.encode(), flags)

    def x509_validate_certificate_ocsp(self, in_cert: str, url: str = "http://ocsp.pki.gov.kz") -> dict[str, bytes]:
        """
        Проверка заданного сертификата на валидность с помощью OCSP.

        http://test.pki.gov.kz/ocsp/ - Тестовый ocsp сервис

        http://ocsp.pki.gov.kz - Боевой ocsp сервис

        :param in_cert: str - Сертификат для проверки.
        :param url: адрес сервиса
        :return: dict[str, bytes] - Словарь, содержащий результат проверки.
        """
        with self._lock:
            return self._kc.x509_validate_certificate(
                in_cert.encode(),
                ValidateType.KC_USE_OCSP,
                url.encode()
            )

    def x509_validate_certificate_crl(self, in_cert: str, crl_path: str) -> dict[str, bytes]:
        """
        Проверка заданного сертификата на валидность с помощью CRL.
        Осуществляет проверку сертификата:
        - проверка срока действия;
        - построение цепочки сертификатов;
        :param in_cert: str - Сертификат для проверки.
        :param crl_path: str - Путь к файлу CRL.
        :return: dict[str, bytes] - Словарь, содержащий результат проверки.
        """
        with self._lock:
            return self._kc.x509_validate_certificate(
                in_cert.encode(),
                ValidateType.KC_USE_CRL,
                crl_path.encode()
            )

    def get_time_from_sign(
            self,
            sign: str,
            flags: t.Optional[t.Iterable[SignatureFlag]] = (
                    SignatureFlag.KC_IN_BASE64,
            )) -> int:
        """
        Извлекает временную метку из подписи.
        :param sign: str - подпись, из которой нужно извлечь временную метку.
        :param flags: флаги
        :return: int - временная метка.
        """
        with self._lock:
            return self._kc.get_time_from_sign(sign.encode(), flags)

    def set_tsa_url(self, url: str = "http://tsp.pki.gov.kz:80"):
        """
        Установка адреса сервиса TSA.
        """
        with self._lock:
            self._kc.set_tsa_url(url.encode())


