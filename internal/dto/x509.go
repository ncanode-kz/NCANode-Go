package dto

// X509InfoRequest - аналог kz.ncanode.dto.request.X509InfoRequest.
type X509InfoRequest struct {
	VerifyRequest
	Certs []string `json:"certs"`
}

// SbaSignRequest - аналог kz.ncanode.dto.request.SbaSignRequest ("sign by
// algorithm" - подпись произвольных данных приватным ключом, не CMS).
type SbaSignRequest struct {
	Data      string        `json:"data"`
	Signer    SignerRequest `json:"signer"`
	TSAPolicy string        `json:"tsaPolicy,omitempty"`
}

// SbaSignResponse - аналог kz.ncanode.dto.response.SbaSignResponse.
type SbaSignResponse struct {
	StatusResponse
	Certificate string `json:"certificate"`
	Signature   string `json:"signature"`
}

// SbaVerifyRequest - аналог kz.ncanode.dto.request.SbaVerifyRequest.
type SbaVerifyRequest struct {
	VerifyRequest
	Certificate string `json:"certificate"`
	Signature   string `json:"signature"`
	Data        string `json:"data"`
}
