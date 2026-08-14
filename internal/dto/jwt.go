package dto

// JwtHeader - аналог JwtEncodeRequest.JwtRequest.JwtHeader.
type JwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// JwtEncodeRequest - аналог kz.ncanode.dto.request.JwtEncodeRequest.
type JwtEncodeRequest struct {
	JWT struct {
		Header  JwtHeader      `json:"header"`
		Payload map[string]any `json:"payload"`
	} `json:"jwt"`
	Key      string `json:"key"`
	Password string `json:"password"`
	KeyAlias string `json:"keyAlias"`
}

// JwtEncodeResponse - аналог kz.ncanode.dto.response.JwtEncodeResponse.
type JwtEncodeResponse struct {
	StatusResponse
	JWT string `json:"jwt"`
}

// JwtDecodeRequest - аналог kz.ncanode.dto.request.JwtDecodeRequest.
type JwtDecodeRequest struct {
	JWT string `json:"jwt"`
	Key string `json:"key"`
}

// JwtDecodeResponse - аналог kz.ncanode.dto.response.JwtDecodeResponse.
type JwtDecodeResponse struct {
	StatusResponse
	Valid bool `json:"valid"`
	JWT   struct {
		Header  map[string]string `json:"header"`
		Payload map[string]any    `json:"payload"`
	} `json:"jwt"`
}
