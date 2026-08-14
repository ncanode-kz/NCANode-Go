package dto

// Pkcs12InfoRequest - аналог kz.ncanode.dto.request.Pkcs12InfoRequest,
// используется и для /pkcs12/info, и для /pkcs12/aliases.
type Pkcs12InfoRequest struct {
	VerifyRequest
	Keys []SignerRequest `json:"keys"`
}

// Pkcs12AliasesResponse - аналог kz.ncanode.dto.response.Pkcs12AliasesResponse.
type Pkcs12AliasesResponse struct {
	StatusResponse
	Aliases [][]string `json:"aliases"`
}
