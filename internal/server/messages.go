package server

// Everything the user can read. The page and the native window show these as they are, so they
// are Turkish; keep them out of the handler code.
const (
	msgInvalidHost         = "Geçersiz istek adresi."
	msgOriginNotAllowed    = "Bu site e-imza bileşenini kullanamaz."
	msgNotFound            = "Böyle bir adres yok."
	msgMethodNotAllowed    = "Bu adres bu yöntemi desteklemiyor."
	msgPlatformUnsupported = "E-imza bileşeni yalnızca Windows'ta çalışır."
	msgListFailed          = "Sertifikalar okunamadı."
	msgBusy                = "Başka bir imzalama işlemi sürüyor."
	msgCertificateNotFound = "Sertifika bulunamadı."
	msgUnsupportedKey      = "Bu sertifikanın anahtar türü desteklenmiyor."
	msgKeyAccessFailed     = "Sertifika anahtarına erişilemedi."
	msgCancelled           = "İmzalama iptal edildi."
	msgNotJSON             = "İstek JSON olmalı."
	msgTooLarge            = "İstek çok büyük (en fazla 50 MB)."
	msgUnreadable          = "İstek okunamadı."
	msgMissingFields       = "Sertifika ve en az bir belge gerekli."
	msgBadDocumentID       = "Her belgenin benzersiz bir kimliği olmalı."
	msgBadFormat           = "Bilinmeyen belge biçimi."
	msgBadBase64           = "Belge verisi geçerli base64 değil."

	msgNotUDF        = "Geçerli bir UDF belgesi değil."
	msgAlreadySigned = "Belge zaten imzalı."
	msgSignFailed    = "Belge imzalanamadı."

	confirmTitle     = "E-imza onayı"
	confirmQuestion  = "İmzalamak istiyor musunuz?"
	confirmLocalPage = "Bu bilgisayardaki sayfa"
	confirmIntro     = "%s aşağıdaki belgeleri imzalamak istiyor.\n\n"
	confirmCert      = "Sertifika: %s\n"
	confirmIdentity  = "Kimlik no: %s\n"
	confirmIssuer    = "Veren: %s\n\n"
	confirmDocuments = "Belgeler (%d):\n"
	confirmMore      = "… ve %d belge daha\n"
)
