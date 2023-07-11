import ctypes


class LibHandle:
    def __init__(self, handle, lib_name):
        self.handle = handle
        self.lib_name = lib_name

    def init(self) -> int:
        self.handle.KC_GetFunctionList()
        status = self.handle.Init()
        return status

    def load_key_store(self, path: str, password: str, store_type=1, alias: str = "") -> int:
        c_password = ctypes.c_char_p(password.encode())
        c_container = ctypes.c_char_p(path.encode())
        c_alias = ctypes.c_char_p(alias.encode())
        return self.handle.KC_LoadKeyStore(
            ctypes.c_int(store_type), c_password, ctypes.c_int(len(password)),
            c_container, ctypes.c_int(len(path)), c_alias
        )


def get_handle(lib_path: str) -> LibHandle:
    lib_name = ctypes.c_char_p(lib_path.encode())
    handle = ctypes.CDLL(lib_name.value, mode=1)
    if handle is not None:
        return LibHandle(handle, lib_name.value)
    raise OSError(f"failed to open library: {lib_name.value}")
