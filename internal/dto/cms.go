package dto

// CmsCreateRequest - аналог kz.ncanode.dto.request.CmsCreateRequest,
// используется и для /cms/sign, и для /cms/sign/add (Cms - существующий CMS,
// нужен только для /sign/add).
type CmsCreateRequest struct {
	CMS       string          `json:"cms"`
	Data      string          `json:"data"`
	Signers   []SignerRequest `json:"signers"`
	WithTSP   bool            `json:"withTsp"`
	TSAPolicy string          `json:"tsaPolicy"`
	Detached  bool            `json:"detached"`
}

// CmsResponse - аналог kz.ncanode.dto.response.CmsResponse.
type CmsResponse struct {
	StatusResponse
	CMS string `json:"cms"`
}

// CmsVerifyRequest - аналог kz.ncanode.dto.request.CmsVerifyRequest.
type CmsVerifyRequest struct {
	VerifyRequest
	CMS  string `json:"cms"`
	Data string `json:"data"`
}

// CmsDataResponse - аналог kz.ncanode.dto.response.CmsDataResponse.
type CmsDataResponse struct {
	StatusResponse
	Data string `json:"data"`
}

// TspInfo - аналог kz.ncanode.dto.tsp.TspInfo.
type TspInfo struct {
	SerialNumber     string  `json:"serialNumber,omitempty"`
	GenTime          *string `json:"genTime"`
	Policy           string  `json:"policy,omitempty"`
	TSA              string  `json:"tsa,omitempty"`
	TSPHashAlgorithm string  `json:"tspHashAlgorithm,omitempty"`
	Hash             string  `json:"hash,omitempty"`
}

// CmsSignerInfo - аналог kz.ncanode.dto.cms.CmsSignerInfo.
type CmsSignerInfo struct {
	Certificates []CertificateInfo `json:"certificates"`
	TSP          *TspInfo          `json:"tsp,omitempty"`
}

// CmsVerificationResponse - аналог kz.ncanode.dto.response.CmsVerificationResponse.
type CmsVerificationResponse struct {
	StatusResponse
	Valid   bool            `json:"valid"`
	Signers []CmsSignerInfo `json:"signers"`
}
