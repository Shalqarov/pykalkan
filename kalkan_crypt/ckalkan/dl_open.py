import ctypes as ct
from typing import Final

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
        if status_code != 0:
            raise Exception(status_code)
        public_cert = public_cert.value.decode().replace(
            "-----BEGIN CERTIFICATE-----", ""
        )
        public_cert = public_cert.replace("-----END CERTIFICATE-----", "")
        public_cert = public_cert.replace("\n", "")
        return public_cert

    def verify_data(self, in_sign: str, in_data: str = "", alias: str = "", flag: int = 16):
        kc_alias = ct.c_char_p(alias.encode())

        kc_in_data = ct.c_char_p(in_data.encode())
        kc_in_data_len = ct.c_int(len(in_data))

        kc_in_sign = ct.pointer(ct.c_char_p(in_sign.encode()))
        kc_in_sign_len = ct.c_int(len(in_sign))

        kc_out_data = ct.create_string_buffer(OUT_DATA_LENGTH)
        kc_out_data_len = ct.c_int(OUT_DATA_LENGTH)

        kc_out_verify_info = ct.create_string_buffer(OUT_VERIFY_INFO_LENGTH)
        kc_out_verify_info_len = ct.c_int(OUT_VERIFY_INFO_LENGTH)

        kc_out_cert = ct.create_string_buffer(OUT_CERT_LENGTH)
        kc_out_cert_len = ct.c_int(OUT_CERT_LENGTH)

        kc_in_cert_id = ct.c_int(0)

        status_code = self.handle.VerifyData(
            kc_alias,
            ct.c_int(flag),
            kc_in_data,
            kc_in_data_len,
            kc_in_sign,
            kc_in_sign_len,
            kc_out_data,
            kc_out_data_len,
            kc_out_verify_info,
            kc_out_verify_info_len,
            kc_in_cert_id,
            kc_out_cert,
            kc_out_cert_len,
        )

        result = {
            'Cert': kc_out_cert.value,
            'Info': kc_out_verify_info.value,
            'Data': kc_out_data.value
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
