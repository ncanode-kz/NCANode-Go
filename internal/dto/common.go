// Package dto содержит JSON request/response структуры, 1:1 совместимые с
// DTO оригинального NCANode (Java) - имена и регистр полей сверены с
// реальными ответами живого Java-сервиса.
package dto

// StatusResponse - базовая часть любого успешного ответа (аналог
// kz.ncanode.dto.response.StatusResponse в Java, через который остальные
// response-DTO встраивают status/message).
type StatusResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

// OK возвращает StatusResponse для успешного ответа (status=200, message=OK -
// то же самое, что Java выставляет по умолчанию в билдерах ответов).
func OK() StatusResponse {
	return StatusResponse{Status: 200, Message: "OK"}
}

// RevocationCheck - способ проверки отозванности сертификата, запрашиваемый
// клиентом (аналог kz.ncanode.dto.certificate.CertificateRevocation).
type RevocationCheck string

const (
	RevocationCheckOCSP RevocationCheck = "OCSP"
	RevocationCheckCRL  RevocationCheck = "CRL"
)

// VerifyRequest - общая часть запросов на верификацию (аналог
// kz.ncanode.dto.request.VerifyRequest).
type VerifyRequest struct {
	RevocationCheck []RevocationCheck `json:"revocationCheck"`
}

func (r VerifyRequest) HasOCSP() bool { return r.has(RevocationCheckOCSP) }
func (r VerifyRequest) HasCRL() bool  { return r.has(RevocationCheckCRL) }

func (r VerifyRequest) has(c RevocationCheck) bool {
	for _, v := range r.RevocationCheck {
		if v == c {
			return true
		}
	}
	return false
}

// SignerRequest - ключ+пароль для подписи (аналог
// kz.ncanode.dto.request.SignerRequest).
type SignerRequest struct {
	Key      string `json:"key"`
	Password string `json:"password"`
	KeyAlias string `json:"keyAlias"`
	// ReferenceURI используется только для XML-подписи (Reference URI="#id") -
	// см. kz.ncanode.service.XmlService.
	ReferenceURI string `json:"referenceUri"`
}
