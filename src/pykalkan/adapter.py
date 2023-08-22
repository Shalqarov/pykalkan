import threading

from .C.kalkan import KCCLient as _KCCLient
from .interface import KalkanInterface


class Adapter(KalkanInterface):
    """
    Adapter
    Класс, представляющий адаптер для криптографической библиотеки Kalkan.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, lib: str):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(Adapter, cls).__new__(cls)
                cls._instance._kc = _KCCLient(lib)
                cls._instance.init()
            return cls._instance

    def init(self):
        """Инициализация библиотеки.."""
        with self._lock:
            self._kc.kc_init()

    def load_key_store(self, cert_path: str, cert_password: str):
        """
        Загружает хранилище ключей из заданного пути к файлу сертификата и пароля.
        :param cert_path: str - Путь к файлу сертификата.
        :param cert_password: str - Пароль для сертификата.
        """
        with self._lock:
            self._kc.load_key_store(cert_path, cert_password)

    def finalize(self):
        """Освобождает ресурсы криптопровайдера KalkanCryptCOM и завершает работу библиотеки."""
        with self._lock:
            self._kc.finalize()

    def x509_export_certificate_from_store(self) -> bytes:
        """
        Экспорт сертификата из хранилища.
        :return: bytes - Экспортированный сертификат.
        """
        with self._lock:
            return self._kc.x509_export_certificate_from_store()

    def x509_load_certificate_from_buffer(self, in_cert: str):
        """
        Загрузка сертификата из памяти.
        :param in_cert: str - сертификат.
        """
        with self._lock:
            self._kc.x509_load_certificate_from_buffer(in_cert)

    def x509_certificate_get_info(self, in_cert: str) -> bytes:
        """
        Обеспечивает получение значений полей/расширений из сертификата.
        :param in_cert: str - Сертификат, для которого необходимо получить информацию.
        :return: bytes - Информация о сертификате.
        """
        with self._lock:
            return self._kc.x509_certificate_get_info(in_cert)

    def sign_data(self, data) -> bytes:
        """
        Подписывает данные.
        :param data - Данные для подписи.
        :return: bytes - Подписанные данные.
        """
        with self._lock:
            return self._kc.sign_data(data)

    def verify_data(self, signature: str, data: str) -> dict[str, bytes]:
        """
        Обеспечивает проверку подписи.
        :param signature: str - Проверяемая подпись.
        :param data: str - Проверяемые данные.
        :return: dict[str, bytes] - Словарь, содержащий результат проверки.
        """
        with self._lock:
            return self._kc.verify_data(signature, data)

    def x509_validate_certificate_ocsp(self, in_cert: str) -> dict[str, bytes]:
        """
        Проверка заданного сертификата на валидность с помощью OCSP.
        :param in_cert: str - Сертификат для проверки.
        :return: dict[str, bytes] - Словарь, содержащий результат проверки.
        """
        with self._lock:
            return self._kc.x509_validate_certificate_ocsp(in_cert)

    def x509_validate_certificate_crl(self, in_cert: str, crl_path: str) -> dict[str, bytes]:
        """
        Проверка заданного сертификата на валидность с помощью CRL.
        :param in_cert: str - Сертификат для проверки.
        :param crl_path: str - Путь к файлу CRL.
        :return: dict[str, bytes] - Словарь, содержащий результат проверки.
        """
        with self._lock:
            return self._kc.x509_validate_certificate_crl(in_cert, crl_path)

    def get_time_from_sign(self, sign: str) -> int:
        """
        Извлекает временную метку из подписи.
        :param sign: str - подпись, из которой нужно извлечь временную метку.
        :return: int - временная метка.
        """
        with self._lock:
            return self._kc.get_time(sign)

    def set_tsa_url(self):
        """
        Установка адреса сервиса TSA.
        """
        with self._lock:
            self._kc.set_tsa_url()
