from ckalkan.kalkan import KCCLient, new_kc_client


class Kalkan:
    def __init__(self, kc: KCCLient):
        self.kc = kc

    def wrap_error(self, code: int):
        pass


def new_kalkan(lib: str) -> Kalkan:
    try:
        kc = new_kc_client(lib)
        return Kalkan(kc)
    except OSError as e:
        raise OSError(f"Error in new_client(): \n{e}")
