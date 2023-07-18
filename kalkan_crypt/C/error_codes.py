def wrap_error(code: int) -> str:
    return errorLabels.get(code, f"Неизвестная ошибка: {code}")


class ErrorCode:
    ErrorCodeOK = 0  # Нет ошибки
    ErrorCodeErrorReadPKCS12 = 149946370  # Невозможно прочитать файл формата pkcs#12
    ErrorCodeErrorOpenPKCS12 = 149946371  # Невозможно открыть файл формата pkcs12
    ErrorCodeInvalidPropID = 149946372  # Недопустимый идентификатор расширения сертификата
    ErrorCodeBufferTooSmall = 149946373  # Размер буфера слишком мал
    ErrorCodeCertParseError = 149946374  # Невозможно разобрать (распарсить) сертификат
    ErrorCodeInvalidFlag = 149946375  # Недопустимый флаг
    ErrorCodeOpenFileErr = 149946376  # Невозможно открыть файл
    ErrorCodeInvalidPassword = 149946377  # Неправильный пароль
    ErrorCodeMemoryError = 149946381  # Невозможно выделить память
    ErrorCodeCheckChainError = 149946382  # Не найден сертификат УЦ или сертификат пользователя при проверки цепочки
    ErrorCodeValidTypeError = 149946384  # Недопустимый тип валидации сертификата
    ErrorCodeBadCRLFormat = 149946385  # Некорректный формат CRL
    ErrorCodeLoadCRLError = 149946386  # Невозможно загрузить CRL
    ErrorCodeLoadCRLsError = 149946387  # Невозможно загрузить CRL-ы
    ErrorCodeUnknownAlg = 149946389  # Неизвестный алгоритм подписи
    ErrorCodeKeyNotFound = 149946390  # Не найден приватный ключ пользователя
    ErrorCodeSignInitError = 149946391  # Невозможно инициализировать менеджера подпи
    ErrorCodeSignError = 149946392  # Не удалось сгенерировать цифровую подпись
    ErrorCodeEncodeError = 149946393  # Ошибка шифрования
    ErrorCodeInvalidFlags = 149946394  # Недопустимые флаги
    ErrorCodeCertNotFound = 149946395  # Не найден сертификат пользователя
    ErrorCodeVerifySignError = 149946396  # Ошибка верификации подписи xml
    ErrorCodeBase64DecodeError = 149946397  # Ошибка дешифровки из Base 64
    ErrorCodeUnknownCMSFormat = 149946398  # Неизвестный формат CMS
    ErrorCodeCACertNotFound = 149946400  # Не найден сертификат УЦ
    ErrorCodeXMLSecInitError = 149946401  # Ошибка инициализации xmlsec
    ErrorCodeLoadTrustedCertsErr = 149946402  # Ошибка загрузки доверенных сертификатов
    ErrorCodeSignInvalid = 149946403  # Недопустимая подпись xml
    ErrorCodeNoSignFound = 149946404  # Не найдена подпись во входных данных
    ErrorCodeDecodeError = 149946405  # Ошибка дешифрования
    ErrorCodeXMLParseError = 149946406  # Невозможно разобрать (распарсить) xml
    ErrorCodeXMLAddIDError = 149946407  # Не удалось добавить атрибут ID
    ErrorCodeXMLInternalError = 149946408  # Ошибка при работе с xml
    ErrorCodeXMLSetSignError = 149946409  # Не удалось подписать xml
    ErrorCodeOpenSSLError = 149946410  # Ошибка openssl
    ErrorCodeNoTokenFound = 149946412  # Не найден токен
    ErrorCodeOCSPAddCertErr = 149946413  # Не удалось добавить сертификат в ocsp
    ErrorCodeOCSPParseURLErr = 149946414  # Не удалось разобрать url
    ErrorCodeOCSPAddHostErr = 149946415  # Не удалось добавить хост
    ErrorCodeOCSPReqErr = 149946416  # Не удалось добавить текущее время в запрос
    ErrorCodeOCSPConnectionErr = 149946417  # Ошибка подключения к OCSP респондеру
    ErrorCodeVerifyNoData = 149946418  # Нет входных данных для верификации
    ErrorCodeIDAttrNotFound = 149946419  # Не найден атрибут ID
    ErrorCodeIDRange = 149946420  # Некорректный идентификатор
    ErrorCodeReaderNotFound = 149946423  # Не найден ридер
    ErrorCodeGetCertPropErr = 149946424  # Не удалось получить значение атрибута
    ErrorCodeSignFormat = 149946425  # Неизвестный формат подписи
    ErrorCodeInDataFormat = 149946426  # Неизвестный формат входных данных
    ErrorCodeOutDataFormat = 149946427  # Неизвестный формат выходных данных
    ErrorCodeVerifyInitError = 149946428  # Невозможно инициализировать менеджера верификации подписи
    ErrorCodeVerifyError = 149946429  # Не удалось верифицировать цифровую подпись
    ErrorCodeHashError = 149946430  # Не удалось хэшировать данные
    ErrorCodeSignHashError = 149946431  # Не удалось подписать хэшированные данные
    ErrorCodeCACertsNotFound = 149946432  # Не найден сертификат УЦ в хранилище сертификато
    ErrorCodeCertTimeInvalid = 149946434  # Срок действия сертификата истек либо еще не нас
    ErrorCodeConvertError = 149946435  # Ошибка записи сертификата в структуру X509
    ErrorCodeTSACreateQuery = 149946436  # Ошибка генерации запроса timestamp
    ErrorCodeCreateObj = 149946437  # Ошибка записи OID в ASN1 структуру
    ErrorCodeCreateNoNce = 149946438  # Ошибка генерации уникального числа
    ErrorCodeHTTPError = 149946439  # Ошибка протокола http
    ErrorCodeCADESBESFailed = 149946440  # Ошибка проверки расширения CADESBES в CMS
    ErrorCodeCADESTFailed = 149946441  # Ошибка проверки подписи токена TSA
    ErrorCodeNoTSAToken = 149946442  # В подписи не присутствует метка TSA
    ErrorCodeInvalidDigestLen = 149946443  # Неправильная длина хэша
    ErrorCodeGenRandError = 149946444  # Ошибка генерации случайного числа
    ErrorCodeSoapNSError = 149946445  # Не найдены заголовки SOAP-сообщений
    ErrorCodeGetPubKey = 149946446  # Ошибка экспорта публичного ключа
    ErrorCodeGetCertInfo = 149946447  # Ошибка получения информации о сертификате
    ErrorCodeFileReadError = 149946448  # Ошибка чтения файла
    ErrorCodeCheckError = 149946449  # Хэш не совпадает
    ErrorCodeZipExtractErr = 149946450  # Невозможно открыть архив
    ErrorCodeNoManifestFile = 149946451  # Не найден MANIFEST
    ErrorCodeVerifyTSHash = 149946452  # не удалось проверить Хэш подписи TS
    ErrorCodeXADESTFailed = 149946453  # XAdES-T: Ошибка проверки подписи
    ErrorCodeOCSPRespStatMalformedRequest = 149946454  # Неправильный запрос
    ErrorCodeOCSPRespStatInternalError = 149946455  # Внутренняя ошибка
    ErrorCodeOCSPRespStatTryLater = 149946456  # Попробуйте позже
    ErrorCodeOCSPRespStatSigRequired = 149946457  # Должны подписать запрос
    ErrorCodeOCSPRespStatUnauthorized = 149946458  # Запрос не авторизован
    ErrorCodeVerifyIssuerSerialV2 = 149946459  # не удалось проверить IssuerSerialV2 в XAdES
    ErrorCodeOCSPCheckCertFromResp = 149946460  # Ошибка проверки сертификата OCSP-респондера
    ErrorCodeCRLExpired = 149946461  # CRL-файл просрочен
    ErrorCodeLibraryNotInitialized = 149946625  # Библиотека не инициализирована
    ErrorCodeEngineLoadErr = 149946880  # Ошибка подключения (загрузки) модуля (engine)
    ErrorCodeParamError = 149947136  # Некорректные входные данные
    ErrorCodeCertStatusOK = 149947392  # Статус сертификата – валидный. Используется при проверке сертификата по OCSP. (не является ошибкой, делается запись в лог)
    ErrorCodeCertStatusRevoked = 149947393  # Статус сертификата – отозван. Используется при проверке сертификата по OCSP.
    ErrorCodeCertStatusUnknown = 149947394  # Статус сертификата – неизвестен. Используется при проверке сертификата по OCSP. Например, не удалось установить издателя сертификата.


errorLabels = {
    ErrorCode.ErrorCodeOK: "Нет ошибки",
    ErrorCode.ErrorCodeErrorReadPKCS12: "Невозможно прочитать файл формата pkcs#12",
    ErrorCode.ErrorCodeErrorOpenPKCS12: "Невозможно открыть файл формата pkcs12",
    ErrorCode.ErrorCodeInvalidPropID: "Недопустимый идентификатор расширения сертификата",
    ErrorCode.ErrorCodeBufferTooSmall: "Размер буфера слишком мал",
    ErrorCode.ErrorCodeCertParseError: "Невозможно разобрать (распарсить) сертификат",
    ErrorCode.ErrorCodeInvalidFlag: "Недопустимый флаг",
    ErrorCode.ErrorCodeOpenFileErr: "Невозможно открыть файл",
    ErrorCode.ErrorCodeInvalidPassword: "Неправильный пароль",
    ErrorCode.ErrorCodeMemoryError: "Невозможно выделить память",
    ErrorCode.ErrorCodeCheckChainError: "Не найден сертификат УЦ или сертификат пользователя при проверки цепочки",
    ErrorCode.ErrorCodeValidTypeError: "Недопустимый тип валидации сертификата",
    ErrorCode.ErrorCodeBadCRLFormat: "Некорректный формат CRL",
    ErrorCode.ErrorCodeLoadCRLError: "Невозможно загрузить CRL",
    ErrorCode.ErrorCodeLoadCRLsError: "Невозможно загрузить CRL-ы",
    ErrorCode.ErrorCodeUnknownAlg: "Неизвестный алгоритм подписи",
    ErrorCode.ErrorCodeKeyNotFound: "Не найден приватный ключ пользователя",
    ErrorCode.ErrorCodeSignInitError: "Невозможно инициализировать менеджера подписи",
    ErrorCode.ErrorCodeSignError: "Не удалось сгенерировать цифровую подпись",
    ErrorCode.ErrorCodeEncodeError: "Ошибка шифрования",
    ErrorCode.ErrorCodeInvalidFlags: "Недопустимые флаги",
    ErrorCode.ErrorCodeCertNotFound: "Не найден сертификат пользователя",
    ErrorCode.ErrorCodeVerifySignError: "Ошибка верификации подписи xml",
    ErrorCode.ErrorCodeBase64DecodeError: "Ошибка дешифровки из Base 64",
    ErrorCode.ErrorCodeUnknownCMSFormat: "Неизвестный формат CMS",
    ErrorCode.ErrorCodeCACertNotFound: "Не найден сертификат УЦ",
    ErrorCode.ErrorCodeXMLSecInitError: "Ошибка инициализации xmlsec",
    ErrorCode.ErrorCodeLoadTrustedCertsErr: "Ошибка загрузки доверенных сертификатов",
    ErrorCode.ErrorCodeSignInvalid: "Недопустимая подпись xml",
    ErrorCode.ErrorCodeNoSignFound: "Не найдена подпись во входных данных",
    ErrorCode.ErrorCodeDecodeError: "Ошибка дешифрования",
    ErrorCode.ErrorCodeXMLParseError: "Невозможно разобрать (распарсить) xml",
    ErrorCode.ErrorCodeXMLAddIDError: "Не удалось добавить атрибут ID",
    ErrorCode.ErrorCodeXMLInternalError: "Ошибка при работе с xml",
    ErrorCode.ErrorCodeXMLSetSignError: "Не удалось подписать xml",
    ErrorCode.ErrorCodeOpenSSLError: "Ошибка openssl",
    ErrorCode.ErrorCodeNoTokenFound: "Не найден токен",
    ErrorCode.ErrorCodeOCSPAddCertErr: "Не удалось добавить сертификат в ocsp",
    ErrorCode.ErrorCodeOCSPParseURLErr: "Не удалось разобрать url",
    ErrorCode.ErrorCodeOCSPAddHostErr: "Не удалось добавить хост",
    ErrorCode.ErrorCodeOCSPReqErr: "Не удалось добавить текущее время в запрос",
    ErrorCode.ErrorCodeOCSPConnectionErr: "Ошибка подключения к OCSP респондеру",
    ErrorCode.ErrorCodeVerifyNoData: "Нет входных данных для верификации",
    ErrorCode.ErrorCodeIDAttrNotFound: "Не найден атрибут ID",
    ErrorCode.ErrorCodeIDRange: "Некорректный идентификатор",
    ErrorCode.ErrorCodeReaderNotFound: "Не найден ридер",
    ErrorCode.ErrorCodeGetCertPropErr: "Не удалось получить значение атрибута",
    ErrorCode.ErrorCodeSignFormat: "Неизвестный формат подписи",
    ErrorCode.ErrorCodeInDataFormat: "Неизвестный формат входных данных",
    ErrorCode.ErrorCodeOutDataFormat: "Неизвестный формат выходных данных",
    ErrorCode.ErrorCodeVerifyInitError: "Невозможно инициализировать менеджера верификации подписи",
    ErrorCode.ErrorCodeVerifyError: "Не удалось верифицировать цифровую подпись",
    ErrorCode.ErrorCodeHashError: "Не удалось хэшировать данные",
    ErrorCode.ErrorCodeSignHashError: "Не удалось подписать хэшированные данные",
    ErrorCode.ErrorCodeCACertsNotFound: "Не найден сертификат УЦ в хранилище сертификатов",
    ErrorCode.ErrorCodeCertTimeInvalid: "Срок действия сертификата истек либо еще не наступил",
    ErrorCode.ErrorCodeConvertError: "Ошибка записи сертификата в структуру X509",
    ErrorCode.ErrorCodeTSACreateQuery: "Ошибка генерации запроса timestamp",
    ErrorCode.ErrorCodeCreateObj: "Ошибка записи OID в ASN1 структуру",
    ErrorCode.ErrorCodeCreateNoNce: "Ошибка генерации уникального числа",
    ErrorCode.ErrorCodeHTTPError: "Ошибка протокола http",
    ErrorCode.ErrorCodeCADESBESFailed: "Ошибка проверки расширения CADESBES в CMS",
    ErrorCode.ErrorCodeCADESTFailed: "Ошибка проверки подписи токена TSA",
    ErrorCode.ErrorCodeNoTSAToken: "В подписи не присутствует метка TSA",
    ErrorCode.ErrorCodeInvalidDigestLen: "Неправильная длина хэша",
    ErrorCode.ErrorCodeGenRandError: "Ошибка генерации случайного числа",
    ErrorCode.ErrorCodeSoapNSError: "Не найдены заголовки SOAP-сообщений",
    ErrorCode.ErrorCodeGetPubKey: "Ошибка экспорта публичного ключа",
    ErrorCode.ErrorCodeGetCertInfo: "Ошибка получения информации о сертификате",
    ErrorCode.ErrorCodeFileReadError: "Ошибка чтения файла",
    ErrorCode.ErrorCodeCheckError: "Хэш не совпадает",
    ErrorCode.ErrorCodeZipExtractErr: "Невозможно открыть архив",
    ErrorCode.ErrorCodeNoManifestFile: "Не найден MANIFEST",
    ErrorCode.ErrorCodeVerifyTSHash: "не удалось проверить Хэш подписи TS",
    ErrorCode.ErrorCodeXADESTFailed: "XAdES-T: Ошибка проверки подписи",
    ErrorCode.ErrorCodeOCSPRespStatMalformedRequest: "Неправильный запрос",
    ErrorCode.ErrorCodeOCSPRespStatInternalError: "Внутренняя ошибка",
    ErrorCode.ErrorCodeOCSPRespStatTryLater: "Попробуйте позже",
    ErrorCode.ErrorCodeOCSPRespStatSigRequired: "Должны подписать запрос",
    ErrorCode.ErrorCodeOCSPRespStatUnauthorized: "Запрос не авторизован",
    ErrorCode.ErrorCodeVerifyIssuerSerialV2: "не удалось проверить IssuerSerialV2 в XAdES",
    ErrorCode.ErrorCodeOCSPCheckCertFromResp: "Ошибка проверки сертификата OCSP-респондера",
    ErrorCode.ErrorCodeCRLExpired: "CRL-файл просрочен",
    ErrorCode.ErrorCodeLibraryNotInitialized: "Библиотека не инициализирована",
    ErrorCode.ErrorCodeEngineLoadErr: "Ошибка подключения (загрузки) модуля (engine)",
    ErrorCode.ErrorCodeParamError: "Некорректные входные данные",
    ErrorCode.ErrorCodeCertStatusOK: "Статус сертификата – валидный. Используется при проверке сертификата по OCSP. ("
                                     "не является ошибкой, делается запись в лог)",
    ErrorCode.ErrorCodeCertStatusRevoked: "Статус сертификата – отозван. Используется при проверке сертификата по OCSP.",
    ErrorCode.ErrorCodeCertStatusUnknown: "Статус сертификата – неизвестен. Используется при проверке сертификата по "
                                          "OCSP. Например, не удалось установить издателя сертификата.",
}
