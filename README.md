# pykalkan

## Установка:

```shell
pip install pykalkan
```

Для работы с ЭЦП (Электронной Цифровой Подписью) используется библиотека Kalkan Crypt. Вам необходимо выполнить
следующие шаги:

1. Установите нужную версию библиотеки Kalkan Crypt из SDK (SDK/C/Linux/C/libs). Например:

   ```bash
   sudo cp -f libkalkancryptwr-64.so.2.0.2 /usr/lib/libkalkancryptwr-64.so
   ```

2. Установите CA (Certificate Authority) сертификаты из папки SDK/C/Linux/ca-certs. В этой папке находятся два типа
   сертификатов: production и test. Для установки сертификатов используйте предоставленные скрипты.

   > Обратите внимание, что при установке сертификатов потребуются права суперпользователя (sudo).

## Пример работы с библиотекой Kalkan Crypt

Вот пример использования библиотеки Kalkan Crypt для проверки ЭЦП на валидность:

```python
import os

from pykalkan import Adapter
from pykalkan.exceptions import ValidateException, KalkanException

lib = "libkalkancryptwr-64.so"


def main(sign: str, verify_data: str):
    try:
        kc = Adapter(lib)
        kc.init()
        res = kc.verify_data(
            sign,
            verify_data,
        )
        cert = res["Cert"].decode()
        kc.x509_validate_certificate_ocsp(cert)
        kc.x509_validate_certificate_crl(cert, os.getenv("CRL_PATH"))
    except ValidateException as ve:
        print(f"Validate failed: {ve}")
    except KalkanException as ke:
        print(f"Kalkan Exception failed: {ke}")
    else:
        kc.finalize()
```

> Внимание! Динамическая библиотека не предназначена для одновременного обращения к ней

На данный момент (на 21.08.23) реализованы следующие функции из библиотеки:

- KC_Init
- KC_LoadKeyStore
- KC_Finalize
- KC_SignData
- KC_VerifyData
- X509ExportCertificateFromStore
- X509LoadCertificateFromStore
- X509CertificateGetInfo
- X509ValidateCertificate (CRL + OCSP)
- TSASetUrl
- GetTimeFromSign
