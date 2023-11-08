import os
import time

import pytest
from dotenv import load_dotenv

from pykalkan import *

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
        with Adapter(LIBRARY) as kc:
            kc.load_key_store(CERT_PATH, CERT_PASSWORD)
            kc.set_tsa_url()
            yield kc
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
    except exceptions.KalkanException as err:
        pytest.fail(str(err))


def test_verify_data(adapter):
    try:
        data = adapter.sign_data(DATA_TO_SIGN)
    except exceptions.KalkanException as err:
        pytest.fail(str(err))
    try:
        adapter.verify_data(data.decode(), DATA_TO_SIGN)
    except exceptions.ValidateException as err:
        pytest.fail(str(err))


def test_validate_cert_ocsp(adapter):
    try:
        data = adapter.sign_data(DATA_TO_SIGN)
    except exceptions.KalkanException as err:
        pytest.fail(str(err))
    try:
        res = adapter.verify_data(data.decode(), DATA_TO_SIGN)
        adapter.x509_validate_certificate_ocsp(res["Cert"].decode())
    except exceptions.ValidateException as err:
        pytest.fail(str(err))


def test_validate_cert_crl(adapter):
    try:
        data = adapter.sign_data(DATA_TO_SIGN)
    except exceptions.KalkanException as err:
        pytest.fail(str(err))
    try:
        res = adapter.verify_data(data.decode(), DATA_TO_SIGN)
        adapter.x509_validate_certificate_crl(res["Cert"].decode(), os.getenv("CRL_PATH"))
    except exceptions.ValidateException as err:
        pytest.fail(str(err))
