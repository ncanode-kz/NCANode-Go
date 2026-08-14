package dto

// XmlSignRequest - аналог kz.ncanode.dto.request.XmlSignRequest.
type XmlSignRequest struct {
	XML             string          `json:"xml"`
	Signers         []SignerRequest `json:"signers"`
	ClearSignatures bool            `json:"clearSignatures"`
	TrimXML         bool            `json:"trimXml"`
}

// XmlSignResponse - аналог kz.ncanode.dto.response.XmlSignResponse (общий
// для /xml/sign и /wsse/sign).
type XmlSignResponse struct {
	StatusResponse
	XML string `json:"xml"`
}

// XmlVerifyRequest - аналог kz.ncanode.dto.request.XmlVerifyRequest (общий
// для /xml/verify и /wsse/verify).
type XmlVerifyRequest struct {
	VerifyRequest
	XML string `json:"xml"`
}

// WsseSignRequest - аналог kz.ncanode.dto.request.WsseSignRequest.
type WsseSignRequest struct {
	XML      string `json:"xml"`
	Key      string `json:"key"`
	Password string `json:"password"`
	KeyAlias string `json:"keyAlias"`
	TrimXML  bool   `json:"trimXml"`
}
