package dto

// PdfSigner - аналог kz.ncanode.dto.request.PdfSignRequest.PdfSigner.
type PdfSigner struct {
	Reason      string        `json:"reason"`
	Location    string        `json:"location"`
	ContactInfo string        `json:"contactInfo"`
	Signer      SignerRequest `json:"signer"`
}

// PdfSignRequest - аналог kz.ncanode.dto.request.PdfSignRequest.
type PdfSignRequest struct {
	PDF       string      `json:"pdf"`
	Signers   []PdfSigner `json:"signers"`
	WithTSP   bool        `json:"withTsp"`
	TSAPolicy string      `json:"tsaPolicy,omitempty"`
}

// PdfSignResponse - аналог kz.ncanode.dto.response.PdfSignResponse.
type PdfSignResponse struct {
	StatusResponse
	PDF string `json:"pdf"`
}

// PdfVerifyRequest - аналог kz.ncanode.dto.request.PdfVerifyRequest.
type PdfVerifyRequest struct {
	VerifyRequest
	PDF string `json:"pdf"`
}

// PdfSignerInfo - аналог kz.ncanode.dto.pdf.PdfSignerInfo.
type PdfSignerInfo struct {
	Valid              bool             `json:"valid"`
	Reason             string           `json:"reason,omitempty"`
	Location           string           `json:"location,omitempty"`
	ContactInfo        string           `json:"contactInfo,omitempty"`
	SignDate           *string          `json:"signDate"`
	Certificate        *CertificateInfo `json:"certificate"`
	SignatureAlgorithm string           `json:"signatureAlgorithm,omitempty"`
	DigestAlgorithm    string           `json:"digestAlgorithm,omitempty"`
}

// PdfVerificationResponse - аналог kz.ncanode.dto.response.PdfVerificationResponse.
type PdfVerificationResponse struct {
	StatusResponse
	Valid   bool            `json:"valid"`
	Signers []PdfSignerInfo `json:"signers"`
}
