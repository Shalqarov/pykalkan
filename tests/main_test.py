import os
import time

import pytest
from dotenv import load_dotenv

from pykalkan import Adapter

load_dotenv()

LIBRARY = "libkalkancryptwr-64.so"
DATA_TO_SIGN = "SGVsbG8sIFdvcmxkIQ=="
CERT_PATH = os.getenv("CERT_PATH")
CERT_PASSWORD = os.getenv("CERT_PASSWORD")


def is_valid_date(timestamp):
    try:
        timestamp = int(timestamp)
        time.gmtime(timestamp)
        return True
    except ValueError:
        return False


@pytest.fixture(scope="module")
def adapter():
    try:
        kc = Adapter(LIBRARY)
        kc.init()
        kc.load_key_store(CERT_PATH, CERT_PASSWORD)
        kc.set_tsa_url()
        yield kc
        kc.finalize()
    except OSError as e:
        assert False, f"Adapter creation fail: {e}"
    except Exception as e:
        pytest.fail(e)


def test_sign_data(adapter):
    try:
        data = adapter.sign_data(DATA_TO_SIGN)
        assert data is not None, "Data signing failed"
        timestamp = adapter.get_time_from_sign(data.decode())
        assert is_valid_date(timestamp), "Invalid time in signed data"
    except Exception as e:
        pytest.fail(str(e))


def test_verify_data(adapter):
    try:
        data = adapter.sign_data(DATA_TO_SIGN)
        adapter.verify_data(data.decode(), DATA_TO_SIGN)
    except Exception as e:
        pytest.fail(str(e))


def test_validate_cert_ocsp(adapter):
    try:
        data = adapter.sign_data(DATA_TO_SIGN)
        res = adapter.verify_data(data.decode(), DATA_TO_SIGN)
        adapter.x509_validate_certificate_ocsp(res["Cert"].decode(), "http://test.pki.gov.kz/ocsp/")
    except Exception as e:
        pytest.fail(str(e))


def test_validate_cert_crl(adapter):
    try:
        data = adapter.sign_data(DATA_TO_SIGN)
        res = adapter.verify_data(data.decode(), DATA_TO_SIGN)
        adapter.x509_validate_certificate_crl(res["Cert"].decode(), os.getenv("CRL_PATH"))
    except Exception as e:
        pytest.fail(str(e))
