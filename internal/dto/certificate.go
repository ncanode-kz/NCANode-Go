package dto

// CertSubject/CertIssuer/Revocation/CertificateInfo - JSON-форма, 1:1 с
// kz.ncanode.dto.certificate.CertificateInfo в Java (сверено с реальными
// ответами живого NCANode на /pkcs12/info, /x509/info, /cms/verify и т.д.).

type CertSubject struct {
	CommonName   string `json:"commonName,omitempty"`
	SurName      string `json:"surName,omitempty"`
	Country      string `json:"country,omitempty"`
	IIN          string `json:"iin,omitempty"`
	BIN          string `json:"bin,omitempty"`
	Organization string `json:"organization,omitempty"`
	DN           string `json:"dn,omitempty"`
}

type CertIssuer struct {
	CommonName string `json:"commonName,omitempty"`
	Country    string `json:"country,omitempty"`
	DN         string `json:"dn,omitempty"`
}

// Revocation - результат одной проверки отозванности (аналог
// kz.ncanode.dto.certificate.CertificateRevocationStatus).
type Revocation struct {
	Revoked        bool    `json:"revoked"`
	By             string  `json:"by"`
	RevocationTime *string `json:"revocationTime"`
	Reason         string  `json:"reason,omitempty"`
}

type CertificateInfo struct {
	Valid        bool         `json:"valid"`
	Revocations  []Revocation `json:"revocations"`
	NotBefore    string       `json:"notBefore"`
	NotAfter     string       `json:"notAfter"`
	KeyUsage     string       `json:"keyUsage"`
	SerialNumber string       `json:"serialNumber"`
	SignAlg      string       `json:"signAlg"`
	KeyUser      []string     `json:"keyUser"`
	PublicKey    string       `json:"publicKey"`
	Signature    string       `json:"signature"`
	Subject      CertSubject  `json:"subject"`
	Issuer       CertIssuer   `json:"issuer"`
}

// VerificationResponse - общий ответ для *verify/*info эндпоинтов (аналог
// kz.ncanode.dto.response.VerificationResponse). Signers - указатели, а не
// значения: при разборе невалидного сертификата в батче (/x509/info)
// Java кладёт в список null вместо объекта, не прерывая обработку остальных -
// здесь это тот же nil-элемент, сериализуемый в JSON null.
type VerificationResponse struct {
	StatusResponse
	Valid   bool               `json:"valid"`
	Signers []*CertificateInfo `json:"signers"`
}
