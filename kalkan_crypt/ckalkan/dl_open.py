import ctypes as ct
import typing as t
from typing import Any, Final

from .enums import CertCode, CertProp, SignatureFlag

OUT_CERT_LENGTH: Final[int] = 64768
OUT_VERIFY_INFO_LENGTH: Final[int] = 64768
OUT_DATA_LENGTH: Final[int] = 28000


class LibHandle:
    """ Хендлер для работы с библиотекой ключей """

    def __init__(self, handle, lib_name):
        self.handle = handle
        self.lib_name = lib_name
        self._alias = ct.create_string_buffer("".encode())

    def kc_init(self) -> int:
        """
        KC_Init() - Инициализация библиотеки.
        :return: 0 При успешном завершении
        """

        self.handle.KC_GetFunctionList()
        return self.handle.Init()

    def kc_load_key_store(
            self, path: str, password: str, store_type=1, alias: str = ""
    ) -> int:
        """
        Загрузка ключей/сертификата их хранилища.
        :param path: название/путь хранилища
        :param password: пароль к хранилищу;
        :param store_type: тип хранилища;
        :param alias: label (alias) сертификата
        :return: 0 При успешном завершении, в противном случае код ошибки
        """

        c_password = ct.c_char_p(password.encode())
        c_container = ct.c_char_p(path.encode())
        c_alias = ct.c_char_p(alias.encode())
        return self.handle.KC_LoadKeyStore(
            ct.c_int(store_type),
            c_password,
            ct.c_int(len(password)),
            c_container,
            ct.c_int(len(path)),
            c_alias,
        )

    def kc_finalize(self):
        """ Освобождает ресурсы криптопровайдера KalkanCryptCOM и завершает работу библиотеки. """
        self.handle.KC_Finalize()

    def x509_export_certificate_from_store(self):
        """ Экспорт сертификата из хранилища. """

        flags = ct.c_int(1)
        cert_len = ct.pointer(ct.c_int(32768))
        public_cert = ct.create_string_buffer(32768)
        status_code = self.handle.X509ExportCertificateFromStore(
            self._alias,
            flags,
            public_cert,
            cert_len,
        )
        public_cert = public_cert.value.decode().replace(
            "-----BEGIN CERTIFICATE-----", ""
        )
        public_cert = public_cert.replace("-----END CERTIFICATE-----", "")
        public_cert = public_cert.replace("\n", "")
        return status_code, public_cert

    def x509_load_certificate_from_buffer(self, in_cert: bytes, cert_code: CertCode = CertCode.KC_CERT_B64) -> int:
        kc_in_cert = ct.c_char_p(in_cert)
        kc_in_cert_len = ct.c_int(len(in_cert))
        kc_cert_code = ct.c_int(cert_code)
        return self.handle.X509LoadCertificateFromBuffer(kc_in_cert, kc_in_cert_len, kc_cert_code)

    def x509_certificate_get_info(
            self,
            in_cert: bytes,
            props: CertProp = CertProp.KC_SUBJECT_ORGUNIT_NAME) -> tuple[int, Any]:
        """
        Обеспечивает получение значений полей/расширений из сертификата.
        Сертификат должен быть предварительно загружен с помощью одной из функций:
        LoadKeyStore(), X509LoadCertificateFromFile(), X509LoadCertificateFromBuffer().
        """
        kc_in_cert = ct.c_char_p(in_cert)
        kc_in_cert_len = ct.c_int(len(in_cert))
        out_data_len = 32768
        out_data = ct.create_string_buffer(out_data_len)
        props = ct.c_int(props)
        status = self.handle.X509CertificateGetInfo(
            kc_in_cert,
            kc_in_cert_len,
            props,
            out_data,
            ct.pointer(ct.c_int(out_data_len))
        )
        return status, out_data.value

    def sign_data(self, data: bytes, flags: t.Iterable[SignatureFlag] = (
            SignatureFlag.KC_SIGN_CMS, SignatureFlag.KC_IN_BASE64, SignatureFlag.KC_OUT_BASE64,
            SignatureFlag.KC_DETACHED_DATA, SignatureFlag.KC_WITH_CERT)):
        """
        Создание подписи на основе переданных данных.

        :param data: Данные
        :param flags: Список флагов
        :return: Подпись
        """
        flags = ct.c_int(sum([flag for flag in flags]))

        data_to_sign = ct.create_string_buffer(data)

        signed_data = ct.create_string_buffer(len(data_to_sign) * 2 + 50000)

        status_code = self.handle.SignData(
            self._alias,
            flags,
            data_to_sign,
            ct.c_int(len(data_to_sign)),
            ct.create_string_buffer(''.encode()),
            len(data_to_sign) * 2 + 50000,
            signed_data,
            ct.pointer(ct.c_int(len(data_to_sign) * 2 + 50000))
        )
        return status_code, signed_data.value

    def verify_data(self, in_sign: bytes, in_data: bytes = b"",
                    flags: t.Iterable[SignatureFlag] = (
                            SignatureFlag.KC_SIGN_CMS, SignatureFlag.KC_IN_BASE64, SignatureFlag.KC_IN2_BASE64,
                            SignatureFlag.KC_DETACHED_DATA, SignatureFlag.KC_WITH_CERT, SignatureFlag.KC_OUT_BASE64
                    )) -> \
            tuple[int, dict[str, Any]]:
        """ Обеспечивает проверку подписи. """
        alias = self._alias

        flags = ct.c_int(sum([flag for flag in flags]))

        data = ct.c_char_p(in_data)
        data_length = ct.c_int(len(in_data))

        inout_sign_length = ct.c_int(len(in_sign))
        inout_sign = (ct.c_ubyte * len(in_sign)).from_buffer_copy(in_sign)

        out_data = ct.create_string_buffer(OUT_DATA_LENGTH)
        out_data_length = ct.byref(ct.c_int(OUT_DATA_LENGTH))

        out_verify_info = ct.create_string_buffer(OUT_VERIFY_INFO_LENGTH)
        out_verify_info_length = ct.byref(ct.c_int(OUT_VERIFY_INFO_LENGTH))

        cert_id = ct.c_int(1)
        out_cert = ct.create_string_buffer(OUT_CERT_LENGTH)
        out_cert_length = ct.byref(ct.c_int(OUT_CERT_LENGTH))

        status_code = self.handle.VerifyData(
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
            'Cert': out_cert.value,
            'Info': out_verify_info.value,
            'Data': out_data.value
        }
        return status_code, result


def get_handle(lib_path: str = "/usr/lib/libkalkancryptwr-64.so") -> LibHandle:
    """
    Подключение библиотеки.
    :param lib_path: путь к библиотеке (/usr/lib/...)
    :return: LibHandle
    """
    lib_name = ct.c_char_p(lib_path.encode())
    handle = ct.CDLL(lib_name.value, mode=1)
    if handle is not None:
        return LibHandle(handle, lib_name.value)
    raise OSError(f"failed to open library: {lib_name.value}")
