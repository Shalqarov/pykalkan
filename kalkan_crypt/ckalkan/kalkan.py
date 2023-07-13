from .dl_open import LibHandle, get_handle


class KCCLient:
    """ Логика вызова методов из библиотеки """

    def __init__(self, handle: LibHandle):
        self.handler = handle

    def kc_init(self) -> int:
        status = self.handler.kc_init()
        return status

    def load_key_store(self, path: str, password: str) -> int:
        return self.handler.kc_load_key_store(path, password)

    def finalize(self):
        self.handler.kc_finalize()

    def x509_export_certificate_from_store(self):
        return self.handler.x509_export_certificate_from_store()

    def sign_data(self, data: str):
        # data_b64 = base64.b64encode(data.encode())
        return self.handler.sign_data(data.encode())

    def verify_data(self, signature):
        return self.handler.verify_data(signature)


def new_kc_client(lib: str) -> KCCLient:
    try:
        handler = get_handle(lib)
        return KCCLient(handler)
    except OSError as e:
        raise OSError(f"Error in new_kc_client():\n {e}")
