## Работа с ЭЦП (Kalkan Crypt)

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

Вот пример использования библиотеки Kalkan Crypt для проверки ЭЦП:

```python
from kalkan_crypt import Adapter, ErrorCode

lib = "libkalkancryptwr-64.so"


def validate_sign(sign: str, verify_data: str) -> tuple[int, str]:
    """
    Функция для валидации ЭЦП
    """
    cli = Adapter(lib)
    status_code, result = cli.verify_data(sign, verify_data)
    if status_code != 0:
        return status_code, "non-valid sign"
    cert = result["Cert"].decode("utf-8")

    status_code, result = cli.x509_validate_certificate_ocsp(cert)
    if status_code == ErrorCode.OCSPConnectionErr:
        status_code, result = cli.x509_validate_certificate_crl(cert)
    if status_code != 0:
        return status_code, "non-valid cert"
    info = result["info"].decode("utf-8")

    status_code, _ = cli.x509_certificate_get_info(cert)
    if status_code != 0:
        return ErrorCode.GetCertPropErr
    return status_code, info
```

На данный момент (на 31.07.23) реализованы следующие функции из библиотеки:

- KC_Init
- KC_LoadKeyStore
- KC_Finalize
- KC_SignData
- KC_VerifyData
- X509ExportCertificateFromStore
- X509LoadCertificateFromStore
- X509CertificateGetInfo
- X509ValidateCertificate (CRL + OCSP)
