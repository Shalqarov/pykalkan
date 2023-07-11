import ctypes


class LibHandle:
    """
    Хендлер для работы с библиотекой ключей
    """

    def __init__(self, handle, lib_name):
        self.handle = handle
        self.lib_name = lib_name

    def kc_init(self) -> int:
        """
        KC_Init() - Инициализация библиотеки.
        :return: 0 При успешном завершении
        """

        self.handle.KC_GetFunctionList()
        return self.handle.Init()

    def load_key_store(self, path: str, password: str, store_type=1, alias: str = "") -> int:
        """
        Загрузка ключей/сертификата их хранилища.
        :param path: название/путь хранилища
        :param password: пароль к хранилищу;
        :param store_type: тип хранилища;
        :param alias: label (alias) сертификата
        :return: 0 При успешном завершении, в противном случае код ошибки
        """

        c_password = ctypes.c_char_p(password.encode())
        c_container = ctypes.c_char_p(path.encode())
        c_alias = ctypes.c_char_p(alias.encode())
        return self.handle.KC_LoadKeyStore(
            ctypes.c_int(store_type), c_password, ctypes.c_int(len(password)),
            c_container, ctypes.c_int(len(path)), c_alias
        )


def get_handle(lib_path: str = "/usr/lib/libkalkancryptwr-64.so") -> LibHandle:
    """
    Подключение библиотеки.
    :param lib_path: путь к библиотеке (/usr/lib/...)
    :return: LibHandle
    """

    lib_name = ctypes.c_char_p(lib_path.encode())
    handle = ctypes.CDLL(lib_name.value, mode=1)
    if handle is not None:
        return LibHandle(handle, lib_name.value)
    raise OSError(f"failed to open library: {lib_name.value}")
