from .ckalkan.kalkan import KCCLient as _KCClient, new_kc_client
from .kalkan_interface import KalkanInterface


class Client(KalkanInterface):
    def __init__(self, kc: _KCClient):
        self._kc = kc

    def init(self) -> int:
        return self._kc.kc_init()

    def load_key_store(self, cert_path: str, cert_password: str) -> int:
        return self._kc.load_key_store(cert_path, cert_password)


def new_client(lib: str) -> Client:
    try:
        kc = new_kc_client(lib)
        return Client(kc)
    except OSError as e:
        raise OSError(f"Error in new_client() /kalkan_crypt/adapter.py:21: \n{e}")
