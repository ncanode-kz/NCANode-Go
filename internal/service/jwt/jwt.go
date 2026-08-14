// Package jwt - HTTP-хендлеры /jwt/encode, /jwt/decode (аналог
// kz.ncanode.service.JwtService).
package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/ncanode-kz/NCANode-Go/internal/app"
	"github.com/ncanode-kz/NCANode-Go/internal/dto"
	"github.com/ncanode-kz/NCANode-Go/internal/httpapi"
	"github.com/ncanode-kz/NCANode-Go/internal/kalkanutil"
)

var errMalformedJWT = errors.New("jwt does not have 3 dot-separated parts")

func RegisterRoutes(s *httpapi.Server, a *app.App) {
	httpapi.Handle(s, "POST /jwt/encode", func(r *http.Request, req dto.JwtEncodeRequest) (dto.JwtEncodeResponse, error) {
		return encode(a, req)
	})
	httpapi.Handle(s, "POST /jwt/decode", func(r *http.Request, req dto.JwtDecodeRequest) (dto.JwtDecodeResponse, error) {
		return decode(a, req)
	})
}

func encode(a *app.App, req dto.JwtEncodeRequest) (dto.JwtEncodeResponse, error) {
	if req.Key == "" {
		return dto.JwtEncodeResponse{}, httpapi.ClientError("key is required", nil)
	}
	if req.JWT.Header.Alg == "" {
		return dto.JwtEncodeResponse{}, httpapi.ClientError("jwt.header.alg is required", nil)
	}

	a.SigningMu.Lock()
	defer a.SigningMu.Unlock()

	if _, err := kalkanutil.LoadSigner(a.Shared, req.Key, req.Password); err != nil {
		return dto.JwtEncodeResponse{}, httpapi.ServerError("failed to load signer", err)
	}

	token, err := a.Shared.SignJWT(req.JWT.Payload, req.JWT.Header.Alg)
	if err != nil {
		return dto.JwtEncodeResponse{}, httpapi.ServerError("failed to sign jwt", err)
	}

	return dto.JwtEncodeResponse{StatusResponse: dto.OK(), JWT: token}, nil
}

// decode реализует /jwt/decode. Как и в Java: структурный разбор
// header/payload не зависит от успеха проверки подписи (валидность подписи -
// отдельное поле valid) - поэтому header/payload декодируются напрямую из
// токена, а не берутся из gokalkan.VerifyJWT (который при неверной подписи
// возвращает nil claims).
func decode(a *app.App, req dto.JwtDecodeRequest) (dto.JwtDecodeResponse, error) {
	header, payload, err := decodeJWTStructure(req.JWT)
	if err != nil {
		return dto.JwtDecodeResponse{}, httpapi.ClientError("malformed JWT", err)
	}

	der, err := base64.StdEncoding.DecodeString(kalkanutil.StripWhitespace(req.Key))
	if err != nil {
		return dto.JwtDecodeResponse{}, httpapi.ClientError("key is not valid base64", err)
	}

	_, verifyErr := a.Shared.VerifyJWT(req.JWT, kalkanutil.PEMFromDER(der))

	resp := dto.JwtDecodeResponse{StatusResponse: dto.OK(), Valid: verifyErr == nil}
	resp.JWT.Header = header
	resp.JWT.Payload = payload

	return resp, nil
}

func decodeJWTStructure(token string) (header map[string]string, payload map[string]any, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, errMalformedJWT
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, nil, err
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, nil, err
	}

	return header, payload, nil
}
