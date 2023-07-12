from .dl_open import LibHandle, get_handle


class KCCLient:
    """ Логика вызова методов из библиотеки """

    def __init__(self, handle: LibHandle):
        self.handler = handle

    def kc_init(self) -> int:
        status = self.handler.kc_init()
        return status

    def load_key_store(self, path: str, password: str) -> int:
        return self.handler.load_key_store(path, password)


def new_kc_client(lib: str) -> KCCLient:
    try:
        handler = get_handle(lib)
        return KCCLient(handler)
    except OSError as e:
        raise OSError(f"Error in new_kc_client():\n {e}")
