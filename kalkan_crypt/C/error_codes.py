def wrap_error(code: int) -> str:
    return errorLabels.get(code, f"Неизвестная ошибка: {code}")


class ErrorCode:
    OK = 0  # Нет ошибки
    ErrorReadPKCS12 = 149946370  # Невозможно прочитать файл формата pkcs#12
    ErrorOpenPKCS12 = 149946371  # Невозможно открыть файл формата pkcs12
    InvalidPropID = 149946372  # Недопустимый идентификатор расширения сертификата
    BufferTooSmall = 149946373  # Размер буфера слишком мал
    CertParseError = 149946374  # Невозможно разобрать (распарсить) сертификат
    InvalidFlag = 149946375  # Недопустимый флаг
    OpenFileErr = 149946376  # Невозможно открыть файл
    InvalidPassword = 149946377  # Неправильный пароль
    MemoryError = 149946381  # Невозможно выделить память
    CheckChainError = 149946382  # Не найден сертификат УЦ или сертификат пользователя при проверки цепочки
    ValidTypeError = 149946384  # Недопустимый тип валидации сертификата
    BadCRLFormat = 149946385  # Некорректный формат CRL
    LoadCRLError = 149946386  # Невозможно загрузить CRL
    LoadCRLsError = 149946387  # Невозможно загрузить CRL-ы
    UnknownAlg = 149946389  # Неизвестный алгоритм подписи
    KeyNotFound = 149946390  # Не найден приватный ключ пользователя
    SignInitError = 149946391  # Невозможно инициализировать менеджера подпи
    SignError = 149946392  # Не удалось сгенерировать цифровую подпись
    EncodeError = 149946393  # Ошибка шифрования
    InvalidFlags = 149946394  # Недопустимые флаги
    CertNotFound = 149946395  # Не найден сертификат пользователя
    VerifySignError = 149946396  # Ошибка верификации подписи xml
    Base64DecodeError = 149946397  # Ошибка дешифровки из Base 64
    UnknownCMSFormat = 149946398  # Неизвестный формат CMS
    CACertNotFound = 149946400  # Не найден сертификат УЦ
    XMLSecInitError = 149946401  # Ошибка инициализации xmlsec
    LoadTrustedCertsErr = 149946402  # Ошибка загрузки доверенных сертификатов
    SignInvalid = 149946403  # Недопустимая подпись xml
    NoSignFound = 149946404  # Не найдена подпись во входных данных
    DecodeError = 149946405  # Ошибка дешифрования
    XMLParseError = 149946406  # Невозможно разобрать (распарсить) xml
    XMLAddIDError = 149946407  # Не удалось добавить атрибут ID
    XMLInternalError = 149946408  # Ошибка при работе с xml
    XMLSetSignError = 149946409  # Не удалось подписать xml
    OpenSSLError = 149946410  # Ошибка openssl
    NoTokenFound = 149946412  # Не найден токен
    OCSPAddCertErr = 149946413  # Не удалось добавить сертификат в ocsp
    OCSPParseURLErr = 149946414  # Не удалось разобрать url
    OCSPAddHostErr = 149946415  # Не удалось добавить хост
    OCSPReqErr = 149946416  # Не удалось добавить текущее время в запрос
    OCSPConnectionErr = 149946417  # Ошибка подключения к OCSP респондеру
    VerifyNoData = 149946418  # Нет входных данных для верификации
    IDAttrNotFound = 149946419  # Не найден атрибут ID
    IDRange = 149946420  # Некорректный идентификатор
    ReaderNotFound = 149946423  # Не найден ридер
    GetCertPropErr = 149946424  # Не удалось получить значение атрибута
    SignFormat = 149946425  # Неизвестный формат подписи
    InDataFormat = 149946426  # Неизвестный формат входных данных
    OutDataFormat = 149946427  # Неизвестный формат выходных данных
    VerifyInitError = 149946428  # Невозможно инициализировать менеджера верификации подписи
    VerifyError = 149946429  # Не удалось верифицировать цифровую подпись
    HashError = 149946430  # Не удалось хэшировать данные
    SignHashError = 149946431  # Не удалось подписать хэшированные данные
    CACertsNotFound = 149946432  # Не найден сертификат УЦ в хранилище сертификато
    CertTimeInvalid = 149946434  # Срок действия сертификата истек либо еще не нас
    ConvertError = 149946435  # Ошибка записи сертификата в структуру X509
    TSACreateQuery = 149946436  # Ошибка генерации запроса timestamp
    CreateObj = 149946437  # Ошибка записи OID в ASN1 структуру
    CreateNoNce = 149946438  # Ошибка генерации уникального числа
    HTTPError = 149946439  # Ошибка протокола http
    CADESBESFailed = 149946440  # Ошибка проверки расширения CADESBES в CMS
    CADESTFailed = 149946441  # Ошибка проверки подписи токена TSA
    NoTSAToken = 149946442  # В подписи не присутствует метка TSA
    InvalidDigestLen = 149946443  # Неправильная длина хэша
    GenRandError = 149946444  # Ошибка генерации случайного числа
    SoapNSError = 149946445  # Не найдены заголовки SOAP-сообщений
    GetPubKey = 149946446  # Ошибка экспорта публичного ключа
    GetCertInfo = 149946447  # Ошибка получения информации о сертификате
    FileReadError = 149946448  # Ошибка чтения файла
    CheckError = 149946449  # Хэш не совпадает
    ZipExtractErr = 149946450  # Невозможно открыть архив
    NoManifestFile = 149946451  # Не найден MANIFEST
    VerifyTSHash = 149946452  # не удалось проверить Хэш подписи TS
    XADESTFailed = 149946453  # XAdES-T: Ошибка проверки подписи
    OCSPRespStatMalformedRequest = 149946454  # Неправильный запрос
    OCSPRespStatInternalError = 149946455  # Внутренняя ошибка
    OCSPRespStatTryLater = 149946456  # Попробуйте позже
    OCSPRespStatSigRequired = 149946457  # Должны подписать запрос
    OCSPRespStatUnauthorized = 149946458  # Запрос не авторизован
    VerifyIssuerSerialV2 = 149946459  # не удалось проверить IssuerSerialV2 в XAdES
    OCSPCheckCertFromResp = 149946460  # Ошибка проверки сертификата OCSP-респондера
    CRLExpired = 149946461  # CRL-файл просрочен
    LibraryNotInitialized = 149946625  # Библиотека не инициализирована
    EngineLoadErr = 149946880  # Ошибка подключения (загрузки) модуля (engine)
    ParamError = 149947136  # Некорректные входные данные
    CertStatusOK = 149947392  # Статус сертификата – валидный. Используется при проверке сертификата по OCSP. (не является ошибкой, делается запись в лог)
    CertStatusRevoked = 149947393  # Статус сертификата – отозван. Используется при проверке сертификата по OCSP.
    CertStatusUnknown = 149947394  # Статус сертификата – неизвестен. Используется при проверке сертификата по OCSP. Например, не удалось установить издателя сертификата.


errorLabels = {
    ErrorCode.OK: "Нет ошибки",
    ErrorCode.ErrorReadPKCS12: "Невозможно прочитать файл формата pkcs#12",
    ErrorCode.ErrorOpenPKCS12: "Невозможно открыть файл формата pkcs12",
    ErrorCode.InvalidPropID: "Недопустимый идентификатор расширения сертификата",
    ErrorCode.BufferTooSmall: "Размер буфера слишком мал",
    ErrorCode.CertParseError: "Невозможно разобрать (распарсить) сертификат",
    ErrorCode.InvalidFlag: "Недопустимый флаг",
    ErrorCode.OpenFileErr: "Невозможно открыть файл",
    ErrorCode.InvalidPassword: "Неправильный пароль",
    ErrorCode.MemoryError: "Невозможно выделить память",
    ErrorCode.CheckChainError: "Не найден сертификат УЦ или сертификат пользователя при проверки цепочки",
    ErrorCode.ValidTypeError: "Недопустимый тип валидации сертификата",
    ErrorCode.BadCRLFormat: "Некорректный формат CRL",
    ErrorCode.LoadCRLError: "Невозможно загрузить CRL",
    ErrorCode.LoadCRLsError: "Невозможно загрузить CRL-ы",
    ErrorCode.UnknownAlg: "Неизвестный алгоритм подписи",
    ErrorCode.KeyNotFound: "Не найден приватный ключ пользователя",
    ErrorCode.SignInitError: "Невозможно инициализировать менеджера подписи",
    ErrorCode.SignError: "Не удалось сгенерировать цифровую подпись",
    ErrorCode.EncodeError: "Ошибка шифрования",
    ErrorCode.InvalidFlags: "Недопустимые флаги",
    ErrorCode.CertNotFound: "Не найден сертификат пользователя",
    ErrorCode.VerifySignError: "Ошибка верификации подписи xml",
    ErrorCode.Base64DecodeError: "Ошибка дешифровки из Base 64",
    ErrorCode.UnknownCMSFormat: "Неизвестный формат CMS",
    ErrorCode.CACertNotFound: "Не найден сертификат УЦ",
    ErrorCode.XMLSecInitError: "Ошибка инициализации xmlsec",
    ErrorCode.LoadTrustedCertsErr: "Ошибка загрузки доверенных сертификатов",
    ErrorCode.SignInvalid: "Недопустимая подпись xml",
    ErrorCode.NoSignFound: "Не найдена подпись во входных данных",
    ErrorCode.DecodeError: "Ошибка дешифрования",
    ErrorCode.XMLParseError: "Невозможно разобрать (распарсить) xml",
    ErrorCode.XMLAddIDError: "Не удалось добавить атрибут ID",
    ErrorCode.XMLInternalError: "Ошибка при работе с xml",
    ErrorCode.XMLSetSignError: "Не удалось подписать xml",
    ErrorCode.OpenSSLError: "Ошибка openssl",
    ErrorCode.NoTokenFound: "Не найден токен",
    ErrorCode.OCSPAddCertErr: "Не удалось добавить сертификат в ocsp",
    ErrorCode.OCSPParseURLErr: "Не удалось разобрать url",
    ErrorCode.OCSPAddHostErr: "Не удалось добавить хост",
    ErrorCode.OCSPReqErr: "Не удалось добавить текущее время в запрос",
    ErrorCode.OCSPConnectionErr: "Ошибка подключения к OCSP респондеру",
    ErrorCode.VerifyNoData: "Нет входных данных для верификации",
    ErrorCode.IDAttrNotFound: "Не найден атрибут ID",
    ErrorCode.IDRange: "Некорректный идентификатор",
    ErrorCode.ReaderNotFound: "Не найден ридер",
    ErrorCode.GetCertPropErr: "Не удалось получить значение атрибута",
    ErrorCode.SignFormat: "Неизвестный формат подписи",
    ErrorCode.InDataFormat: "Неизвестный формат входных данных",
    ErrorCode.OutDataFormat: "Неизвестный формат выходных данных",
    ErrorCode.VerifyInitError: "Невозможно инициализировать менеджера верификации подписи",
    ErrorCode.VerifyError: "Не удалось верифицировать цифровую подпись",
    ErrorCode.HashError: "Не удалось хэшировать данные",
    ErrorCode.SignHashError: "Не удалось подписать хэшированные данные",
    ErrorCode.CACertsNotFound: "Не найден сертификат УЦ в хранилище сертификатов",
    ErrorCode.CertTimeInvalid: "Срок действия сертификата истек либо еще не наступил",
    ErrorCode.ConvertError: "Ошибка записи сертификата в структуру X509",
    ErrorCode.TSACreateQuery: "Ошибка генерации запроса timestamp",
    ErrorCode.CreateObj: "Ошибка записи OID в ASN1 структуру",
    ErrorCode.CreateNoNce: "Ошибка генерации уникального числа",
    ErrorCode.HTTPError: "Ошибка протокола http",
    ErrorCode.CADESBESFailed: "Ошибка проверки расширения CADESBES в CMS",
    ErrorCode.CADESTFailed: "Ошибка проверки подписи токена TSA",
    ErrorCode.NoTSAToken: "В подписи не присутствует метка TSA",
    ErrorCode.InvalidDigestLen: "Неправильная длина хэша",
    ErrorCode.GenRandError: "Ошибка генерации случайного числа",
    ErrorCode.SoapNSError: "Не найдены заголовки SOAP-сообщений",
    ErrorCode.GetPubKey: "Ошибка экспорта публичного ключа",
    ErrorCode.GetCertInfo: "Ошибка получения информации о сертификате",
    ErrorCode.FileReadError: "Ошибка чтения файла",
    ErrorCode.CheckError: "Хэш не совпадает",
    ErrorCode.ZipExtractErr: "Невозможно открыть архив",
    ErrorCode.NoManifestFile: "Не найден MANIFEST",
    ErrorCode.VerifyTSHash: "не удалось проверить Хэш подписи TS",
    ErrorCode.XADESTFailed: "XAdES-T: Ошибка проверки подписи",
    ErrorCode.OCSPRespStatMalformedRequest: "Неправильный запрос",
    ErrorCode.OCSPRespStatInternalError: "Внутренняя ошибка",
    ErrorCode.OCSPRespStatTryLater: "Попробуйте позже",
    ErrorCode.OCSPRespStatSigRequired: "Должны подписать запрос",
    ErrorCode.OCSPRespStatUnauthorized: "Запрос не авторизован",
    ErrorCode.VerifyIssuerSerialV2: "не удалось проверить IssuerSerialV2 в XAdES",
    ErrorCode.OCSPCheckCertFromResp: "Ошибка проверки сертификата OCSP-респондера",
    ErrorCode.CRLExpired: "CRL-файл просрочен",
    ErrorCode.LibraryNotInitialized: "Библиотека не инициализирована",
    ErrorCode.EngineLoadErr: "Ошибка подключения (загрузки) модуля (engine)",
    ErrorCode.ParamError: "Некорректные входные данные",
    ErrorCode.CertStatusOK: "Статус сертификата – валидный. Используется при проверке сертификата по OCSP. ("
                            "не является ошибкой, делается запись в лог)",
    ErrorCode.CertStatusRevoked: "Статус сертификата – отозван. Используется при проверке сертификата по OCSP.",
    ErrorCode.CertStatusUnknown: "Статус сертификата – неизвестен. Используется при проверке сертификата по "
                                 "OCSP. Например, не удалось установить издателя сертификата.",
}
