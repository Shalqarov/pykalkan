import os
import time

import pytest
from dotenv import load_dotenv

from pykalkan import Adapter
from pykalkan.exceptions import KalkanException, ValidateException, ErrorCode

load_dotenv()

library = "libkalkancryptwr-64.so.2.0.2"


@pytest.mark.parametrize(
    "path,password",
    [
        (os.getenv("CERT_PATH"), os.getenv("CERT_PASSWORD")),
    ],
)
def test_main(path, password):
    try:
        kc = Adapter(library)
        kc.init()
        kc.set_tsa_url()
        kc.load_key_store(path, password)
        data = kc.sign_data("SGVsbG8sIFdvcmxkIQ==")
        if not is_valid_date(kc.get_time_from_sign(data.decode())):
            raise KalkanException(ErrorCode.INVALID_TIME, "GET TIME")
        res = kc.verify_data(
            data.decode(),
            "SGVsbG8sIFdvcmxkIQ==",
        )
        cert = res["Cert"].decode()
        kc.x509_validate_certificate_ocsp(cert)
        kc.x509_validate_certificate_crl(cert, os.getenv("CRL_PATH"))
    except ValidateException as ve:
        assert False, f"Validate failed: {ve}"
    except KalkanException as ke:
        assert False, f"Kalkan Exception failed: {ke}"
    else:
        kc.finalize()


def is_valid_date(timestamp):
    try:
        timestamp = int(timestamp)
        time.gmtime(timestamp)
        return True
    except ValueError:
        return False
