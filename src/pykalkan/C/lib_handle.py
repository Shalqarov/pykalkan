import ctypes as ct
import typing as t

from pykalkan.enums import CertCode, CertProp, SignatureFlag, ValidateType
from pykalkan.exceptions import KalkanException, ValidateException

VERIFY_OUT_DATA_LENGTH: t.Final[int] = 28000
VERIFY_OUT_VERIFY_INFO_LENGTH: t.Final[int] = 64768
VERIFY_OUT_CERT_LENGTH: t.Final[int] = 64768

VALIDATE_DATA_LENGTH: t.Final[int] = 8192

CERT_SIZE: t.Final[int] = 32768


class LibHandle:
    """Хендлер для работы с dynamic lib"""

    __instance = None

    def __new__(cls, lib_path: str):
        if cls.__instance is None:
            cls.__instance = super(LibHandle, cls).__new__(cls)
            cls.__instance.handle = ct.CDLL(lib_path, mode=1)
            cls.__instance._alias = ct.create_string_buffer("".encode())
            if not cls.__instance.handle:
                raise OSError(f"failed to open library: {lib_path}")
        return cls.__instance

    @staticmethod
    def __handle_error(error_code: int, method_name: str, info: t.Optional[str] = None):
        if error_code != 0:
            raise ValidateException(
                error_code, method_name, info
            ) if info else KalkanException(error_code, method_name)

    def kc_init(self):
        """
        KC_Init() - Инициализация библиотеки.
        """
        self.__handle_error(self.handle.Init(), "KC_INIT")

    def kc_load_key_store(self, path: str, password: str, store_type: int, alias: str):
        """
        Загрузка ключей/сертификата их хранилища.
        :param path: название/путь хранилища
        :param password: пароль к хранилищу;
        :param store_type: тип хранилища;
        :param alias: label (alias) сертификата
        """

        c_password = ct.c_char_p(password.encode())
        c_container = ct.c_char_p(path.encode())
        c_alias = ct.c_char_p(alias.encode())
        err_code = self.handle.KC_LoadKeyStore(
            ct.c_int(store_type),
            c_password,
            ct.c_int(len(password)),
            c_container,
            ct.c_int(len(path)),
            c_alias,
        )
        self.__handle_error(err_code, "KC_LoadKeyStore")

    def kc_finalize(self):
        """Освобождает ресурсы криптопровайдера KalkanCryptCOM и завершает работу библиотеки."""
        self.handle.KC_Finalize()

    def x509_export_certificate_from_store(self) -> bytes:
        """
        Экспорт сертификата из хранилища.
        :return: tuple(статус ошибки, сертификат)
        """

        flags = ct.c_int(1)
        cert_len = ct.pointer(ct.c_int(CERT_SIZE))
        public_cert = ct.create_string_buffer(CERT_SIZE)

        err_code = self.handle.X509ExportCertificateFromStore(
            self._alias,
            flags,
            public_cert,
            cert_len,
        )
        self.__handle_error(err_code, "X509ExportCertificateFromStore")
        return public_cert.value

    def x509_load_certificate_from_buffer(self, in_cert: bytes, cert_code: CertCode):
        """
        Загрузка сертификата из памяти.

        :param in_cert:  сертификат в виде строки в байтах;
        :param cert_code:  кодировка сертификата (см. enums.py CertCode).
        """

        kc_in_cert = ct.c_char_p(in_cert)
        kc_in_cert_len = ct.c_int(len(in_cert))
        kc_cert_code = ct.c_int(cert_code)
        err_code = self.handle.X509LoadCertificateFromBuffer(
            kc_in_cert, kc_in_cert_len, kc_cert_code
        )
        self.__handle_error(err_code, "X509LoadCertificateFromBuffer")

    def x509_certificate_get_info(self, in_cert: bytes, prop: CertProp) -> bytes:
        """
        Обеспечивает получение значений полей/расширений из сертификата.
        Сертификат должен быть предварительно загружен с помощью одной из функций:
         - LoadKeyStore(),
         - X509LoadCertificateFromFile(),
         - X509LoadCertificateFromBuffer().
        :param in_cert:  сертификат в виде строки в байтах;
        :param prop: идентификатор полей/расширений сертификата (см. enums.py CertProp)

        :return: info: bytes(информация по заданному флагу)
        """
        kc_in_cert = ct.c_char_p(in_cert)
        kc_in_cert_len = ct.c_int(len(in_cert))

        out_data_len = 32768
        out_data = ct.create_string_buffer(out_data_len)

        kc_prop = ct.c_int(prop)

        err_code = self.handle.X509CertificateGetInfo(
            kc_in_cert,
            kc_in_cert_len,
            kc_prop,
            out_data,
            ct.pointer(ct.c_int(out_data_len)),
        )
        self.__handle_error(err_code, "X509CertificateGetInfo")
        return out_data.value

    def sign_data(self, data: bytes, flags: t.Iterable[SignatureFlag]) -> bytes:
        """
        Подписывает данные.

        :param data: входные данные;
        :param flags: список флагов
        :return: bytes(подпись в виде base64(По Умолчанию см. документацию KalkanCrypt))
        """
        flags = ct.c_int(sum([flag for flag in flags]))

        data_to_sign = ct.create_string_buffer(data)

        signed_data = ct.create_string_buffer(len(data_to_sign) * 2 + 50000)

        err_code = self.handle.SignData(
            self._alias,
            flags,
            data_to_sign,
            ct.c_int(len(data_to_sign)),
            ct.create_string_buffer("".encode()),
            len(data_to_sign) * 2 + 50000,
            signed_data,
            ct.pointer(ct.c_int(len(data_to_sign) * 2 + 50000)),
        )
        self.__handle_error(err_code, "SignData")
        return signed_data.value

    def verify_data(self, in_sign: bytes, in_data: bytes, flags: t.Iterable[SignatureFlag]) -> dict[str, bytes]:
        """
        Обеспечивает проверку подписи.
        :param in_sign: подписанные входные данные;
        :param in_data: входные данные для сверки;
        :param flags: флаги для верификации;

        :return: dict(верифицированные данные)
        """
        alias = self._alias

        flags = ct.c_int(sum([flag for flag in flags]))

        data = ct.c_char_p(in_data)
        data_length = ct.c_int(len(in_data))

        inout_sign_length = ct.c_int(len(in_sign))
        inout_sign = ct.c_char_p(in_sign)

        out_data = ct.create_string_buffer(VERIFY_OUT_DATA_LENGTH)
        out_data_length = ct.byref(ct.c_int(VERIFY_OUT_DATA_LENGTH))

        out_verify_info = ct.create_string_buffer(VERIFY_OUT_VERIFY_INFO_LENGTH)
        out_verify_info_length = ct.byref(ct.c_int(VERIFY_OUT_VERIFY_INFO_LENGTH))

        cert_id = ct.c_int(1)
        out_cert = ct.create_string_buffer(VERIFY_OUT_CERT_LENGTH)
        out_cert_length = ct.byref(ct.c_int(VERIFY_OUT_CERT_LENGTH))

        err_code = self.handle.VerifyData(
            alias,
            flags,
            data,
            data_length,
            inout_sign,
            inout_sign_length,
            out_data,
            out_data_length,
            out_verify_info,
            out_verify_info_length,
            cert_id,
            out_cert,
            out_cert_length,
        )
        result = {
            "Cert": out_cert.value,
            "Info": out_verify_info.value,
            "Data": out_data.value,
        }
        self.__handle_error(err_code, "VerifyData", result.get("Info"))
        return result

    def x509_validate_certificate(
            self,
            in_cert: bytes,
            valid_type: ValidateType,
            valid_path: bytes,
    ) -> dict[str, bytes]:
        """
        Осуществляет проверку сертификата:
         - проверка срока действия;
         - построение цепочки сертификатов;
         - проверка отозванности по OCSP или CRL.

        http://test.pki.gov.kz/ocsp/ - Тестовый ocsp сервис

        http://ocsp.pki.gov.kz - Боевой ocsp сервис

        :param in_cert: сертификат в виде строки в байтах
        :param valid_type: тип проверки (OCSP/CRL). По умолчанию OCSP (см. enums.py ValidateType)
        :param valid_path: Путь к валидации:
            - при OCSP указать сайт;
            - при CRL - путь к файлу
            (по умолчанию OCSP url)

        :return: dict(результат_запроса)
        """
        kc_in_cert = ct.c_char_p(in_cert)
        kc_in_cert_len = ct.c_int(len(in_cert))

        kc_valid_path = ct.c_char_p(valid_path)

        kc_valid_type = ct.c_int(valid_type)

        out_info = ct.create_string_buffer(VALIDATE_DATA_LENGTH)
        out_info_len = ct.c_int(VALIDATE_DATA_LENGTH)

        resp = ct.create_string_buffer(VALIDATE_DATA_LENGTH)
        resp_len = ct.c_int(VALIDATE_DATA_LENGTH)

        err_code = self.handle.X509ValidateCertificate(
            kc_in_cert,
            kc_in_cert_len,
            kc_valid_type,
            kc_valid_path,
            ct.c_int(0),
            out_info,
            ct.pointer(out_info_len),
            ct.c_int(SignatureFlag.KC_NOCHECKCERTTIME),
            resp,
            ct.pointer(resp_len),
        )
        res = {
            "response": resp.value,
            "info": out_info.value,
        }
        self.__handle_error(err_code, "X509ValidateCertificate", res.get("info"))
        return res

    def get_time_from_sign(self, in_data: bytes, flags: t.Iterable[SignatureFlag]) -> int:
        """
        Получить время подписи.
        :param in_data: подпись
        :param flags: флаги для функции(см. Документацию SDK)
        :return: int(unix time)
        """
        kc_in_data = ct.c_char_p(in_data)
        kc_in_data_length = ct.c_int(len(in_data))

        flags = ct.c_int(sum([flag for flag in flags]))
        kc_in_sig_id = ct.c_int(0)

        out_time = ct.pointer(ct.c_longlong(0))

        err_code = self.handle.KC_GetTimeFromSig(
            kc_in_data,
            kc_in_data_length,
            flags,
            kc_in_sig_id,
            out_time,
        )
        self.__handle_error(err_code, "KC_GetTimeFromSig")
        return out_time.contents.value

    def set_tsa_url(self, url: bytes):
        kc_url = ct.c_char_p(url)
        self.handle.KC_TSASetUrl(kc_url)
