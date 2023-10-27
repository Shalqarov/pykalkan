# pykalkan

## Установка:

```shell
pip install pykalkan
```

## Начало работы

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

> Внимание! Динамическая библиотека не предназначена для одновременного обращения к ней
---

### Подключение библиотеки и загрузка хранилища ключей

```python
from pykalkan import Adapter

lib = "libkalkancryptwr-64.so"

# Инициализация происходит в контекстном менеждере
# При выходе из контекста происходит finalize()
with Adapter(lib) as adapter:
    adapter.load_key_store(CERT_PATH, CERT_PASSWORD)
    adapter.set_tsa_url()
```

---

### Подпись данных в виде base64 строки

```python
...
data = "SGVsbG8sIFdvcmxkIQ=="

signed_data = adapter.sign_data(data)
...
```

---

### Проверка подписи на валидность и отозванность *(OCSP или CRL)*

```python
...
res = adapter.verify_data(signed_data, data_to_verify)

cert = res.get("Cert").decode()

validate_result = adapter.x509_validate_certificate_ocsp(cert)  # OCSP
#  или
validate_result = adapter.x509_validate_certificate_crl(cert, path_to_crl_file)  # CRL
...
```

---
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
