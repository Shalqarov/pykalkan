from ckalkan.error_codes import ErrorCode
from ckalkan.kalkan import KCCLient, new_kc_client


def wrap_error(code: int) -> str:
    return ErrorCode(code).__str__()


class Kalkan:
    def __init__(self, kc: KCCLient):
        self.kc = kc


def new_kalkan(lib: str) -> Kalkan:
    try:
        kc = new_kc_client(lib)
        return Kalkan(kc)
    except OSError as e:
        raise OSError(f"Error in new_client(): \n{e}")
