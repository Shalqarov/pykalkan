import os
import sys
import time

import pytest
from dotenv import load_dotenv

from kalkan_crypt.C.error_codes import KalkanException, ValidateException, ErrorCode
from kalkan_crypt.adapter import Adapter

load_dotenv()

library = "libkalkancryptwr-64.so.2.0.2"


@pytest.mark.parametrize(
    "path,password",
    [
        (os.getenv("CERT_PATH"), os.getenv("CERT_PASSWORD")),
    ],
)
def test_main(path, password):
    cli = Adapter(library)
    try:
        cli.init()
        cli.set_tsa_url()
        cli.load_key_store(path, password)
        data = cli.sign_data("SGVsbG8sIFdvcmxkIQ==")
        if not is_valid_date(cli.get_time_from_sign(data.decode())):
            raise KalkanException(ErrorCode.InvalidTime, "GET TIME")
        res = cli.verify_data(data.decode("utf-8"), "SGVsbG8sIFdvcmxkIQ==")
        _ = cli.x509_validate_certificate(res["Cert"].decode())
    except ValidateException as ve:
        print(f"Validate failed: {ve}")
        sys.exit(1)
    except KalkanException as ke:
        print(f"Kalkan Exception failed: {ke}")
        sys.exit(1)
    finally:
        cli.finalize()


def is_valid_date(timestamp):
    try:
        timestamp = int(timestamp)
        time.gmtime(timestamp)
        return True
    except ValueError:
        return False
