import os
import sys

import pytest
from dotenv import load_dotenv

from kalkan_crypt.C.error_codes import wrap_error
from kalkan_crypt.adapter import Adapter

load_dotenv()

library = "libkalkancryptwr-64.so.2.0.2"

cert_path = "gost.p12"
cert_password = "Qwerty12"  # Test


@pytest.mark.parametrize(
    "sign,data",
    [
        (os.getenv("TEST_SIGN_BIN"), os.getenv("TEST_DATA_BIN")),
        (os.getenv("TEST_SIGN_IIN"), os.getenv("TEST_DATA_IIN")),
    ],
)
def test(sign, data):
    cli = Adapter(library)
    status = cli.init()
    if status != 0:
        assert False, f"Lib Init failed: {wrap_error(status)}"

    status, res = cli.verify_data(sign, data)
    if status != 0:
        assert False, f"Verify Data failed: {wrap_error(status)}"
    if "Verify - FAILED" in res["Info"].decode("utf-8"):
        assert False, f"Verify Data failed: {res['Info']}"

    status, res = cli.x509_certificate_get_info(res["Cert"].decode("utf-8"))
    if sign == os.getenv("TEST_SIGN_BIN"):
        if status != 0:
            assert False, f"Get Info failed: {wrap_error(status)}"
        if not res.decode("utf-8").startswith("OU=BIN"):
            assert (
                False
            ), f"Certificate get info failed, must start with OU=BIN...: {res}"
    else:
        if status == 0:
            assert False, f"get info must fail with IIN: {wrap_error(status)}"

    cli.finalize()


def main():
    cli = Adapter(library)
    status = cli.init()
    if status != 0:
        print(f"Lib Init failed: {wrap_error(status)}")
        sys.exit(1)

    print(cli.load_key_store(os.getenv("CERT_PATH"), os.getenv("CERT_PASSWORD")))

    _, data = cli.sign_data("dGVzdA==")

    status, res = cli.verify_data(data.decode("utf-8"), os.getenv("TEST_DATA_IIN"))
    if status != 0:
        print(f"Verify Data failed: {wrap_error(status)}")
        sys.exit(1)
    if "Verify - FAILED" in res["Info"].decode("utf-8"):
        print(f"Verify Data failed: {wrap_error(status)}")
        sys.exit(1)

    print(res["Info"].decode("utf-8"))
    status, validated = cli.x509_validate_certificate(res["Cert"].decode("utf-8"))
    print(f"{status} , response: {validated['response']},   info: {validated['info']}")
    cli.finalize()


if __name__ == "__main__":
    main()
